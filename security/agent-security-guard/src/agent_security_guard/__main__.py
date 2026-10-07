"""Command-line interface.

    python -m agent_security_guard scan "<text>" [--source ... --wrap]
    python -m agent_security_guard scan --file PATH [--source ... --wrap]
    python -m agent_security_guard check-action --json action.json
    python -m agent_security_guard audit --last 50 [--db PATH]
    python -m agent_security_guard audit --verify [--db PATH]

Exit codes, so that a script can act on the answer:

    0  allowed (``check-action``), or the command did what it was asked
    1  denied (``check-action``), or the audit trail does not verify
    2  the command could not be carried out as written: bad arguments, an
       unreadable file, a policy file or an action the guard cannot apply
    3  not allowed as it stands: a human has to confirm (``check-action``)

Only 0 means "go ahead". ``check-action`` used to exit with 0 for everything
but a denial, so ``check-action ... && run-it`` ran what still needed a
confirmation.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional

from .adapter import GuardAdapter
from .audit import AuditLog
from .modes import is_known_mode
from .policy import load_config
from .scanner import scan_input
from .types import (
    AgentAction,
    DataSensitivity,
    Decision,
    GuardContext,
    OriginTrust,
    UserIntentOrigin,
)
from .wrapper import wrap_untrusted


EXIT_ALLOWED = 0
EXIT_DENIED = 1
EXIT_UNUSABLE = 2
EXIT_NEEDS_CONFIRMATION = 3


class _Unusable(Exception):
    """The command cannot be carried out as it was written."""


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent_security_guard",
        description="Deterministic transition policy engine for agents.",
        epilog="Exit codes: 0 allowed/done, 1 denied or trail broken, "
               "2 cannot be carried out as written, 3 needs confirmation.",
    )
    parser.add_argument("--config", default=None, help="Path to guard.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan content and report provenance/risk")
    scan_p.add_argument(
        "text", nargs="?", default=None,
        help="The text to scan. Always taken as text, also when it names a file",
    )
    scan_p.add_argument(
        "--file", default=None, metavar="PATH",
        help="Scan the contents of this file instead ('-' for standard input)",
    )
    scan_p.add_argument("--source", default="unknown")
    scan_p.add_argument("--channel", default="unknown")
    scan_p.add_argument("--source-kind", default=None)
    scan_p.add_argument("--url", default=None)
    scan_p.add_argument("--wrap", action="store_true", help="Print the safe data block")

    check_p = sub.add_parser("check-action", help="Evaluate a planned action")
    check_p.add_argument("--json", required=True, help="JSON file: {action, context}")
    check_p.add_argument("--audit", action="store_true", help="Record the decision")

    audit_p = sub.add_parser("audit", help="Show recent audit events")
    audit_p.add_argument("--last", type=int, default=50)
    audit_p.add_argument(
        "--verify", action="store_true",
        help="Check the hash chain of the trail; exit 1 if it is broken",
    )
    audit_p.add_argument("--db", default=None, help="Audit DB/JSONL path override")
    audit_p.add_argument("--backend", default=None, choices=["sqlite", "jsonl"])

    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except ValueError as exc:
        print(f"error: {args.config}: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE

    commands = {"scan": _cmd_scan, "check-action": _cmd_check_action, "audit": _cmd_audit}
    try:
        return commands[args.command](args, config)
    except _Unusable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE


def _cmd_scan(args, config) -> int:
    if (args.text is None) == (args.file is None):
        raise _Unusable("give either the text to scan or --file PATH, not both and not neither")
    metadata: Dict[str, Any] = {}
    if args.file is not None:
        content = _read_file(args.file)
        if args.file != "-":
            metadata["path"] = args.file
    else:
        # The argument is the text. It used to be opened as a file whenever a
        # file of that name existed, so text that came from somewhere else
        # chose which file was read and, with --wrap, printed.
        content = args.text
        if _names_a_file(content):
            print(
                f"note: {content!r} was scanned as text. "
                f"To scan the file of that name, use --file.",
                file=sys.stderr,
            )
    if args.source_kind:
        metadata["source_kind"] = args.source_kind
    if args.url:
        metadata["url"] = args.url
    report = scan_input(content, args.source, args.channel, metadata, config)
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    if args.wrap:
        print("\n" + wrap_untrusted(report))
    return 0


def _cmd_check_action(args, config) -> int:
    try:
        with open(args.json, "r", encoding="utf-8") as handle:
            spec = json.load(handle)
    except OSError as exc:
        raise _Unusable(f"{args.json}: {exc.strerror or exc}")
    except ValueError as exc:
        raise _Unusable(f"{args.json} is not valid JSON: {exc}")
    action, context = _read_spec(spec, config)

    audit = AuditLog(config=config) if args.audit else None
    adapter = GuardAdapter(config=config, audit=audit)
    decision = adapter.guard_action(action, context)
    if audit is not None:
        audit.close()
    print(json.dumps(decision.to_dict(), indent=2, ensure_ascii=False))
    if decision.decision in (Decision.ALLOW, Decision.ALLOW_WITH_WARNING):
        return EXIT_ALLOWED
    if decision.decision is Decision.DENY:
        return EXIT_DENIED
    return EXIT_NEEDS_CONFIRMATION


def _cmd_audit(args, config) -> int:
    backend = args.backend or config.audit.get("backend", "sqlite")
    path = args.db
    kwargs: Dict[str, Any] = {"config": config, "backend": backend}
    if path:
        kwargs["path" if backend == "sqlite" else "jsonl_path"] = path
    log = AuditLog(**kwargs)
    if args.verify:
        check = log.verify()
        log.close()
        print(json.dumps(check.to_dict(), indent=2, ensure_ascii=False))
        return 0 if check.ok else 1
    rows = log.last(args.last)
    log.close()
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #


def _read_file(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError as exc:
        raise _Unusable(f"{path}: {exc.strerror or exc}")


def _names_a_file(text: str) -> bool:
    try:
        return os.path.isfile(text)
    except (OSError, ValueError):  # too long for a name, or a null byte in it
        return False


_ACTION_KEYS = (
    "kind", "target", "method", "payload", "desired_memory_lane",
    "memory_source", "metadata",
)
_CONTEXT_ENUMS = {
    "origin_trust": (OriginTrust, OriginTrust.UNKNOWN),
    "data_sensitivity": (DataSensitivity, DataSensitivity.PUBLIC),
    "user_intent_origin": (UserIntentOrigin, UserIntentOrigin.UNKNOWN),
}
_CONTEXT_FLAGS = (
    "no_write_scope_active", "short_confirmation",
    "previous_action_was_explicitly_authorized",
    "requested_action_from_nonuser_context",
)
_CONTEXT_KEYS = (
    "mode", "current_channel", "chain_id", "workspace_root", "domain_allowlist",
) + tuple(_CONTEXT_ENUMS) + _CONTEXT_FLAGS


def _read_spec(spec: Any, config) -> tuple:
    """The action and the context of a ``check-action`` file.

    Anything in it that cannot be used as written is an error. A file whose
    ``action`` was missing or misspelled used to be evaluated as an action
    without a kind, which is allowed, and a misspelled ``data_sensitivity``
    as public: a script got "go ahead" for a question it never asked.
    """
    if not isinstance(spec, dict):
        raise _Unusable("the file must hold one JSON object: {\"action\": {...}, \"context\": {...}}")
    _only_known(spec, ("action", "context"), "the file")
    action = spec.get("action")
    if not isinstance(action, dict):
        raise _Unusable("\"action\" is missing or is not an object")
    _only_known(action, _ACTION_KEYS, "action")
    if not (isinstance(action.get("kind"), str) and action["kind"].strip()):
        raise _Unusable("action.kind is missing: it names what is to be done")
    context = spec.get("context", {})
    if not isinstance(context, dict):
        raise _Unusable("\"context\" is not an object")
    _only_known(context, _CONTEXT_KEYS, "context")
    return _build_action(action), _build_context(context, config)


def _only_known(mapping: Dict[str, Any], known: tuple, where: str) -> None:
    unknown = sorted(str(key) for key in mapping if key not in known)
    if unknown:
        raise _Unusable(
            f"{where} has no setting {', '.join(repr(key) for key in unknown)} "
            f"(there are: {', '.join(known)})"
        )


def _build_action(spec: Dict[str, Any]) -> AgentAction:
    return AgentAction(
        kind=spec.get("kind", ""),
        target=spec.get("target", ""),
        method=spec.get("method"),
        payload=spec.get("payload"),
        desired_memory_lane=spec.get("desired_memory_lane"),
        memory_source=spec.get("memory_source"),
        metadata=spec.get("metadata", {}) or {},
    )


def _build_context(spec: Dict[str, Any], config) -> GuardContext:
    mode = spec.get("mode", config.mode)
    if not is_known_mode(mode):
        raise _Unusable(f"context.mode: {mode!r} is not a mode (monitor, autonomous-safe, strict)")
    for flag in _CONTEXT_FLAGS:
        if not isinstance(spec.get(flag, False), bool):
            raise _Unusable(f"context.{flag}: expected true or false, got {spec[flag]!r}")
    return GuardContext(
        mode=mode,
        current_channel=spec.get("current_channel", ""),
        chain_id=spec.get("chain_id"),
        workspace_root=spec.get("workspace_root"),
        domain_allowlist=spec.get("domain_allowlist", config.domain_allowlist),
        config=config,
        **{key: _enum(key, spec.get(key)) for key in _CONTEXT_ENUMS},
        **{flag: spec.get(flag, False) for flag in _CONTEXT_FLAGS},
    )


def _enum(key: str, value: Any):
    enum_cls, default = _CONTEXT_ENUMS[key]
    if value is None or value == "":
        return default
    try:
        return enum_cls(value)
    except ValueError:
        raise _Unusable(
            f"context.{key}: {value!r} is not one of "
            f"{', '.join(member.value for member in enum_cls)}"
        )


if __name__ == "__main__":
    sys.exit(main())

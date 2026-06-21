"""Command-line interface.

    python -m agent_security_guard scan <file-or-text> [--source ... --wrap]
    python -m agent_security_guard check-action --json action.json
    python -m agent_security_guard audit --last 50 [--db PATH]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional

from .adapter import GuardAdapter
from .audit import AuditLog
from .policy import load_config
from .scanner import scan_input
from .types import (
    AgentAction,
    DataSensitivity,
    GuardContext,
    OriginTrust,
    UserIntentOrigin,
)
from .wrapper import wrap_untrusted


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent_security_guard",
        description="Deterministic transition policy engine for agents.",
    )
    parser.add_argument("--config", default=None, help="Path to guard.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan content and report provenance/risk")
    scan_p.add_argument("input", help="A file path or literal text")
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
    audit_p.add_argument("--db", default=None, help="Audit DB/JSONL path override")
    audit_p.add_argument("--backend", default=None, choices=["sqlite", "jsonl"])

    args = parser.parse_args(argv)
    config = load_config(args.config)

    if args.command == "scan":
        return _cmd_scan(args, config)
    if args.command == "check-action":
        return _cmd_check_action(args, config)
    if args.command == "audit":
        return _cmd_audit(args, config)
    parser.error(f"unknown command {args.command}")
    return 2


def _cmd_scan(args, config) -> int:
    content = _read_input(args.input)
    metadata: Dict[str, Any] = {}
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
    with open(args.json, "r", encoding="utf-8") as handle:
        spec = json.load(handle)
    action = _build_action(spec.get("action", {}))
    context = _build_context(spec.get("context", {}), config)

    audit = AuditLog(config=config) if args.audit else None
    adapter = GuardAdapter(config=config, audit=audit)
    decision = adapter.guard_action(action, context)
    if audit is not None:
        audit.close()
    print(json.dumps(decision.to_dict(), indent=2, ensure_ascii=False))
    return 0 if decision.decision.value != "deny" else 1


def _cmd_audit(args, config) -> int:
    backend = args.backend or config.audit.get("backend", "sqlite")
    path = args.db
    kwargs: Dict[str, Any] = {"config": config, "backend": backend}
    if path:
        kwargs["path" if backend == "sqlite" else "jsonl_path"] = path
    log = AuditLog(**kwargs)
    rows = log.last(args.last)
    log.close()
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #


def _read_input(value: str) -> str:
    if os.path.exists(value):
        with open(value, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return value


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
    return GuardContext(
        mode=spec.get("mode", config.mode),
        origin_trust=_enum(OriginTrust, spec.get("origin_trust"), OriginTrust.UNKNOWN),
        data_sensitivity=_enum(DataSensitivity, spec.get("data_sensitivity"), DataSensitivity.PUBLIC),
        user_intent_origin=_enum(UserIntentOrigin, spec.get("user_intent_origin"), UserIntentOrigin.UNKNOWN),
        current_channel=spec.get("current_channel", ""),
        chain_id=spec.get("chain_id"),
        workspace_root=spec.get("workspace_root"),
        domain_allowlist=spec.get("domain_allowlist", config.domain_allowlist),
        config=config,
    )


def _enum(enum_cls, value, default):
    if not value:
        return default
    try:
        return enum_cls(value)
    except ValueError:
        return default


if __name__ == "__main__":
    sys.exit(main())

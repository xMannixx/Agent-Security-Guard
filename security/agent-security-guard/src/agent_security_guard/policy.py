"""Policy core: configuration + the deterministic hard-rule matrix.

``decide_action`` is the heart of the guard. It evaluates hard, deterministic
rules; the risk score (attached later by ``check_action``) never overrides a
hard decision. The guiding invariant:

    A source's trust does not grant it authority over an action.

Trust ("may this give instructions?") and sensitivity ("how bad if it leaks?")
are kept as two independent axes throughout.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlsplit

from . import _miniyaml, config_check
from .actions import recognized_by_name_only, sends_to_remote
from .host_tools import UNTRUSTED_CONTENT_TOOLS
from .memory_lanes import (
    CONVERSATION,
    NO_LANE,
    OBSERVATION,
    PERSONAL_LANES,
    PRIVILEGED_LANES,
    UNKNOWN_LANE,
    read_lane,
    read_source,
    source_is_untrusted,
    validated_memory_lanes,
)
from .modes import MODE_STRICT, effective_mode, normalize_mode
from .types import (
    ActionTier,
    AgentAction,
    DataSensitivity,
    Decision,
    GuardConfig,
    GuardContext,
    GuardDecision,
    OriginTrust,
    ReasonCode,
    UserIntentOrigin,
)


# --------------------------------------------------------------------------- #
# Defaults + loading
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG: Dict[str, Any] = {
    "mode": "autonomous-safe",
    "domain_allowlist": [],
    "tiers": {
        "read_only": "allow",
        "local_read": "allow",
        "external_write": "require_confirmation",
        "shell_from_user": "require_confirmation",
        "shell_from_untrusted": "deny",
        "install_from_user": "require_confirmation",
        "install_from_untrusted": "deny",
        "config_change": "require_confirmation",
        "memory_external_to_evidence": "allow_with_warning",
        "memory_external_to_identity": "require_confirmation",
        "memory_external_to_preference": "require_confirmation",
        "memory_external_to_authorization": "deny",
        "memory_external_to_procedural": "deny",
        # A write to authorization / procedural memory on a trusted origin that
        # does not state where the fact comes from. Those lanes are written
        # from direct observation only, and nobody said this is one.
        "memory_unsourced_to_privileged": "require_confirmation",
        # A memory write from an untrusted source that names no lane, or one
        # the guard cannot read. It cannot be told from a privileged write.
        # Declare the lane in `memory_lanes` rather than loosening this.
        "memory_external_to_unknown_lane": "deny",
        "download_inspect": "allow",
        "download_then_execute_untrusted": "deny",
        "download_then_execute_user": "require_confirmation",
        # After a secret was read in the chain: a GET-like request to a URL
        # that has room for data (query string, credentials, body). Not a
        # denial, because such requests are common; a plain GET stays free.
        "read_with_data_after_secret": "require_confirmation",
        # After untrusted content (a web page, search results) was read in the
        # chain: a shell command, file write, install, config change, external
        # write or self-modification. The content may be what proposed it, so
        # the user is asked. Reads and unrecognized tools stay free, and so does
        # an action the host reports as explicitly ordered by the user.
        "after_untrusted_content": "require_confirmation",
        # What to do with an action kind the guard does not recognize. Blocking
        # here is what took hosts down in 0.2.x: an unknown *tool name* is not
        # evidence of danger. Only `strict` mode stops and asks.
        "unknown_action": "allow_with_warning",
        # ...unless the host itself says untrusted content proposed it. That is
        # evidence: untrusted content has no authority over an action the guard
        # cannot tell from a write. Declare the tool in `tool_tiers` to lift it.
        "unknown_action_from_untrusted": "deny",
        # A file write by a host file tool (write_file, patch, ...) on a trusted
        # origin. Not tunable: from untrusted content it is denied.
        "local_write": "allow_with_warning",
        "local_write_from_untrusted": "deny",
        # A host tool the guard recognized by its name (terminal, bash, ...),
        # on a trusted origin with nothing pointing at danger. The host never
        # opted into a confirmation flow for it, so asking would block it the
        # way 0.2.x blocked every host tool. Set to require_confirmation if the
        # host can surface a prompt.
        "recognized_host_tool": "allow_with_warning",
    },
    # Tiers for the host's own tools, for names the guard does not know or
    # reads wrongly: {tool name: tier}. Wins over the built-in tables.
    "tool_tiers": {},
    # Writing these with a file tool changes the agent's own future behavior,
    # so it is held to the self-modification bar, not treated as a plain write.
    "self_modification_paths": ["SKILL.md", "guard.yaml"],
    # The host's own names for memory lanes: {lane name: one of identity,
    # preference, evidence, authorization, procedural}.
    "memory_lanes": {},
    # Tools whose result is content from outside the machine (glob patterns).
    "untrusted_content_tools": list(UNTRUSTED_CONTENT_TOOLS),
    # The plugin wraps the results of those tools as data blocks.
    "wrap_tool_results": True,
    # Only true secret material. Broad developer-file globs (*.db, *.log,
    # settings.json, config.py, ...) used to land here, which marked ordinary
    # project files as sensitive and then blocked every later external write
    # via the exfiltration chain. Add project-specific paths deliberately.
    "sensitive_paths": [
        ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
        "*.kdbx", "id_rsa", "id_rsa.*", "id_ed25519", "id_ed25519_sk",
        "id_ecdsa", "id_ecdsa_sk", "id_dsa", ".ssh/", ".aws/",
        ".gcp/", ".azure/", ".kube/", ".gnupg/", ".npmrc", ".pypirc", ".netrc",
        ".git-credentials", ".pgpass", ".vault-token", "secrets.*",
        "credentials.*", "token.json", "auth.json",
        "application_default_credentials.json",
        # By path, not by name: `.docker/` and `environ` alone are ordinary.
        "*.docker/config.json", "*/proc/*/environ",
    ],
    # Match credential *values*, not the mere mention of a credential word.
    # `(?i)api[_-]?key` alone classified any doc or config that talks about API
    # keys as SECRET, which then denied external writes.
    #
    # Every pattern has to stay linear in its input: the scanner runs them
    # over whole web pages. A run of characters followed by a required
    # character is the shape to watch; the JWT pattern may only start at the
    # beginning of such a run for that reason.
    "secret_patterns": [
        # `name = value`, also where the name is a quoted key: "api_key": "..."
        r"(?i)api[_-]?key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._\-]{16,}",
        r"(?i)secret[_-]?key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._\-]{16,}",
        r"(?i)access[_-]?token[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._\-]{16,}",
        r"(?i)password[\"']?\s*[:=]\s*[\"']?[^\s\"']{8,}",
        r"(?i)secret[_-]?access[_-]?key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}",
        r"(?i)bearer\s+[A-Za-z0-9._-]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"github_pat_[A-Za-z0-9_]{40,}",
        r"glpat-[A-Za-z0-9_\-]{20,}",
        r"sk-[A-Za-z0-9]{20,}",
        r"(?<![A-Za-z0-9])sk-(?:ant|proj|svcacct|admin|or)-[A-Za-z0-9_\-]{20,}",
        r"xox[baprs]-[A-Za-z0-9-]{10,}",
        # A JWT: three base64url parts, the first two beginning with `{"`.
        r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        # A connection URL with a password in it. Not one whose password is a
        # placeholder (`<password>`, `${DB_PASS}`, `password`) or repeats the
        # user name (`postgres:postgres@`): those are examples and dev defaults.
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|rediss?|amqps?|mssql)(?:\+[a-z0-9]+)?"
        r"://([^\s:/@]*):"
        r"(?!\1@|(?:pass(?:word|wd)?|pwd|secret|changeme|example|x{3,})@|\$[{(a-z_]|[<{\[*]|%s)"
        r"[^\s:/@]{3,}@",
        r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----",
    ],
    "audit": {
        "backend": "sqlite",
        "path": "guard-audit.db",
        "jsonl_path": "guard-audit.jsonl",
    },
    # What to do when the guard itself cannot evaluate an action (import
    # failure, broken config, unwritable audit sink).
    #   degrade  -> block only kinds that are dangerous by name, allow the rest
    #   deny_all -> block everything (0.2.x behaviour; bricks the host)
    "on_error": "degrade",
    # Opt-in: derive no-write-scope / short-confirmation from raw user text.
    # Off by default because natural phrasing ("ok", "nur lesen") otherwise
    # denied every state-changing action.
    "scope_from_text": False,
    "limits": {
        "max_content_chars": 20000,
        "max_history_events": 50,
        # How many recent actions count as "the current chain" when the host
        # supplies no chain_id. Without this, one sensitive read poisoned every
        # external write for the rest of the session.
        "chain_window": 12,
    },
}


_MERGED_SECTIONS = ("tiers", "audit", "limits", "tool_tiers", "memory_lanes")


def load_config(path: Optional[str] = None) -> GuardConfig:
    """Load ``guard.yaml`` merged over built-in defaults.

    A missing file yields the defaults. A file that cannot be read, or that
    holds an entry the guard cannot apply as written (an unknown setting, an
    unknown mode, a pattern that does not compile, text where a list belongs),
    raises ``ValueError`` naming every such entry: a security policy is
    applied as its operator wrote it or not at all, never as something else.
    """
    merged: Dict[str, Any] = _deep_copy_defaults()
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            loaded = _miniyaml.load(handle.read())
        if not isinstance(loaded, dict):
            raise ValueError("guard.yaml must be a mapping at the top level")
        found = config_check.problems(
            loaded,
            DEFAULT_CONFIG,
            _DECISION_BY_NAME,
            {"tool_tiers": _validated_tool_tiers, "memory_lanes": validated_memory_lanes},
        )
        if found:
            raise ValueError(
                f"{len(found)} entr{'y' if len(found) == 1 else 'ies'} cannot be "
                "applied as written: " + "; ".join(found)
            )
        for key, value in loaded.items():
            if key in _MERGED_SECTIONS and isinstance(value, dict):
                merged[key] = {**merged.get(key, {}), **value}
            else:
                merged[key] = value
    return GuardConfig(
        mode=merged["mode"],
        domain_allowlist=_texts(merged.get("domain_allowlist")),
        tiers={key: str(value).strip().lower() for key, value in merged["tiers"].items()},
        sensitive_paths=_texts(merged.get("sensitive_paths")),
        secret_patterns=_texts(merged.get("secret_patterns")),
        audit=dict(merged.get("audit", {})),
        limits=dict(merged.get("limits", {})),
        on_error=str(merged.get("on_error", "degrade")).strip().lower(),
        scope_from_text=config_check.as_bool(merged.get("scope_from_text", False)),
        tool_tiers=_validated_tool_tiers(merged.get("tool_tiers")),
        self_modification_paths=_texts(merged.get("self_modification_paths")),
        untrusted_content_tools=[
            pattern.strip().lower()
            for pattern in _texts(merged.get("untrusted_content_tools"))
        ],
        wrap_tool_results=config_check.as_bool(merged.get("wrap_tool_results", True)),
        memory_lanes=validated_memory_lanes(merged.get("memory_lanes")),
    )


def _texts(value: Any) -> List[str]:
    """A list setting as a list of strings (``- 8080`` is the text ``8080``)."""
    return [str(item) for item in (value or [])]


def _validated_tool_tiers(raw: Any) -> Dict[str, str]:
    """``tool_tiers`` as {lower-case tool name: tier value}; raises on a typo.

    A misspelled tier must not quietly leave the tool unclassified.
    """
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("tool_tiers must be a mapping of tool name to tier")
    known = {tier.value for tier in ActionTier}
    result: Dict[str, str] = {}
    for name, tier in raw.items():
        value = str(tier).strip().lower()
        if value not in known:
            raise ValueError(
                f"tool_tiers.{name}: unknown tier {tier!r} "
                f"(expected one of {', '.join(sorted(known))})"
            )
        result[str(name).strip().lower()] = value
    return result


def _deep_copy_defaults() -> Dict[str, Any]:
    return {
        "mode": DEFAULT_CONFIG["mode"],
        "domain_allowlist": list(DEFAULT_CONFIG["domain_allowlist"]),
        "tiers": dict(DEFAULT_CONFIG["tiers"]),
        "sensitive_paths": list(DEFAULT_CONFIG["sensitive_paths"]),
        "secret_patterns": list(DEFAULT_CONFIG["secret_patterns"]),
        "audit": dict(DEFAULT_CONFIG["audit"]),
        "limits": dict(DEFAULT_CONFIG["limits"]),
        "on_error": DEFAULT_CONFIG["on_error"],
        "scope_from_text": DEFAULT_CONFIG["scope_from_text"],
        "tool_tiers": dict(DEFAULT_CONFIG["tool_tiers"]),
        "self_modification_paths": list(DEFAULT_CONFIG["self_modification_paths"]),
        "untrusted_content_tools": list(DEFAULT_CONFIG["untrusted_content_tools"]),
        "wrap_tool_results": DEFAULT_CONFIG["wrap_tool_results"],
        "memory_lanes": dict(DEFAULT_CONFIG["memory_lanes"]),
    }


# --------------------------------------------------------------------------- #
# Predicates
# --------------------------------------------------------------------------- #


def path_is_sensitive(path: str, patterns: List[str]) -> bool:
    """Glob-match a path against sensitive-path patterns."""
    return path_matches(path, patterns)


def path_matches(path: str, patterns: List[str], ignore_case: bool = False) -> bool:
    """Glob-match a path against a pattern list.

    Patterns ending in ``/`` match a directory anywhere in the path; other
    patterns match the basename or the full normalized path.
    """
    if not path:
        return False
    normalized = path.replace("\\", "/").strip()
    if ignore_case:
        normalized = normalized.lower()
        patterns = [pattern.lower() for pattern in patterns]
    basename = normalized.rsplit("/", 1)[-1]
    segments = [seg for seg in normalized.split("/") if seg]
    for pattern in patterns:
        if pattern.endswith("/"):
            dir_name = pattern[:-1]
            if dir_name in segments:
                return True
            continue
        if fnmatch.fnmatch(basename, pattern) or fnmatch.fnmatch(normalized, pattern):
            return True
    return False


def domain_allowed(target: str, allowlist: List[str]) -> bool:
    """True if the target URL/host matches an allowlisted domain (or subdomain)."""
    host = _extract_host(target)
    if not host:
        return False
    for allowed in allowlist:
        allowed = allowed.strip().lower()
        if not allowed:
            continue
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def is_loopback_target(target: str) -> bool:
    """True if the target addresses this machine (never leaves the host)."""
    host = _extract_host(target)
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # A name is not an address, whatever it starts with: 127.evil.example
        # resolves wherever its owner points it.
        return False
    # 0.0.0.0 and :: reach this host when used as a destination.
    return address.is_loopback or address.is_unspecified


def _extract_host(target: str) -> str:
    """Host of a URL or ``host[:port][/path]`` string; ``""`` if it is unclear.

    Parsed the way a client parses it, so that ``https://evil.example#@localhost``
    or ``...?@localhost`` is read as evil.example. Where clients disagree (a
    backslash or whitespace in the authority) there is no safe answer, and no
    host means neither the loopback nor the allowlist shortcut applies.
    """
    if not target:
        return ""
    value = target.strip()
    # urlsplit drops tabs and newlines before parsing; a client may not.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return ""
    if "://" not in value:
        value = "//" + value
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
    except ValueError:
        return ""
    if "\\" in parts.netloc or any(ch.isspace() for ch in parts.netloc):
        return ""
    return host.rstrip(".").lower()


def _untrusted(context: GuardContext) -> bool:
    return context.origin_trust.is_untrusted


def resolve_mode(context: GuardContext) -> str:
    """The mode in force for this evaluation (env override > config > context).

    A context that went through ``GuardAdapter`` already carries the mode the
    session fixed at creation (``mode_resolved``); the environment is not read
    again for it, so a later env change cannot loosen a running session.
    """
    configured = context.mode or (context.config.mode if context.config else None)
    if context.mode_resolved:
        return normalize_mode(configured)
    return effective_mode(configured)


_DECISION_BY_NAME = {
    "allow": Decision.ALLOW,
    "allow_with_warning": Decision.ALLOW_WITH_WARNING,
    "transform": Decision.TRANSFORM,
    "require_confirmation": Decision.REQUIRE_CONFIRMATION,
    "deny": Decision.DENY,
}


def tier_setting(
    context: GuardContext, key: str, default: Decision
) -> Decision:
    """Resolve a tunable per-tier decision from ``guard.yaml``.

    Only the operator-tunable paths consult this (external write, shell/install
    from a trusted origin, config change, reads, unknown actions). The
    untrusted-origin denials are deliberately NOT tunable: softening those would
    remove the guarantee the guard exists for.
    """
    tiers = context.config.tiers if context.config else None
    if not tiers:
        tiers = DEFAULT_CONFIG["tiers"]
    return _DECISION_BY_NAME.get(str(tiers.get(key, "")).strip().lower(), default)


def _suggested_by_untrusted(context: GuardContext) -> bool:
    """Whether the intent behind the action came from untrusted content.

    A bare confirmation ("yes") only authorizes an action when it is NOT a
    relay of an untrusted-originated suggestion. So an explicit
    ``UNTRUSTED_SUGGESTION`` counts, and a ``HUMAN_CONFIRMATION`` counts too
    when the origin is untrusted (the classic social-engineering relay:
    a web page proposes a command and the user merely says "yes").
    """
    intent = context.user_intent_origin
    if intent is UserIntentOrigin.UNTRUSTED_SUGGESTION:
        return True
    if intent is UserIntentOrigin.HUMAN_CONFIRMATION and context.origin_trust.is_untrusted:
        return True
    return False


# --------------------------------------------------------------------------- #
# Hard-rule matrix
# --------------------------------------------------------------------------- #

# Tiers that change state (local, remote, or the agent's own behavior). The
# user-scope gates below apply only to these; read-only tiers always pass.
STATE_CHANGING_TIERS = frozenset(
    {
        ActionTier.EXECUTION,
        ActionTier.INSTALL,
        ActionTier.EXTERNAL_WRITE,
        ActionTier.LOCAL_WRITE,
        ActionTier.CONFIG_CHANGE,
        ActionTier.MEMORY_WRITE,
        ActionTier.SELF_MODIFICATION,
        ActionTier.DOWNLOAD,
        ActionTier.SECRET_HANDLING,
    }
)


def is_state_changing(tier: ActionTier) -> bool:
    return tier in STATE_CHANGING_TIERS


def decide_action(
    action: AgentAction, tier: ActionTier, context: GuardContext
) -> GuardDecision:
    """Evaluate the deterministic hard-rule matrix for a single action.

    User-scope gates run first and apply to every state-changing tier:
    an explicit no-write scope, or an ambiguous short confirmation that does
    not trace back to a prior explicit authorization, hard-denies before any
    per-tier allow rule can fire.
    """
    if is_state_changing(tier):
        scope_decision = _decide_user_scope_gates(context)
        if scope_decision is not None:
            return scope_decision

    if tier in _REQUEST_TIERS and _sends_secret(action, context):
        # "Read-only" describes the remote side. The request itself is data
        # leaving the machine, whatever the method.
        return _deny(
            ReasonCode.SECRET_EXTERNAL_SEND,
            "Request to a remote host carries secret-class content; denied "
            "(exfiltration).",
        )

    if tier is ActionTier.READ_ONLY:
        return _tuned(
            tier_setting(context, "read_only", Decision.ALLOW),
            ReasonCode.ALLOW_READ_ONLY,
            "Read-only action; allowed.",
        )

    if tier is ActionTier.LOCAL_READ:
        return _decide_local_read(context)

    if tier is ActionTier.EXECUTION:
        return _decide_execution(action, context)

    if tier is ActionTier.LOCAL_WRITE:
        return _decide_local_write(action, context)

    if tier is ActionTier.DOWNLOAD:
        return _decide(
            Decision.ALLOW_WITH_WARNING,
            ReasonCode.ALLOW_DOWNLOAD_INSPECT,
            "Download allowed; executing the artifact is gated separately.",
        )

    if tier is ActionTier.INSTALL:
        return _decide_install(action, context)

    if tier is ActionTier.EXTERNAL_WRITE:
        return _decide_external_write(action, context)

    if tier is ActionTier.MEMORY_WRITE:
        return _decide_memory_write(action, context)

    if tier is ActionTier.CONFIG_CHANGE:
        return _decide_config_change(action, context)

    if tier is ActionTier.SELF_MODIFICATION:
        return _decide_self_modification(action, context)

    if tier is ActionTier.SECRET_HANDLING:
        return _deny(
            ReasonCode.SECRET_EXTERNAL_SEND,
            "Handling/sending secret material externally is denied.",
        )

    return _decide_unknown_action(context)


# Tiers whose action may be a request to a remote host without being a write.
# A host's own web tools (`web_extract`, `browser_navigate`) are unrecognized
# kinds; left out, a secret in their URL was not looked at.
_REQUEST_TIERS = (ActionTier.READ_ONLY, ActionTier.DOWNLOAD, ActionTier.UNKNOWN)


def _sends_secret(action: AgentAction, context: GuardContext) -> bool:
    return context.data_sensitivity is DataSensitivity.SECRET and sends_to_remote(
        action, context.config
    )


def _decide_unknown_action(context: GuardContext) -> GuardDecision:
    """An action kind the guard does not recognize.

    Blocking here is what made 0.2.x unusable: a host forwards its own tool
    names (``list_dir``, ``dashboard_query``, ...), none of which are in the
    kind table, so every one of them came back as ``require_confirmation`` and
    the host treated that as blocked. An unrecognized *name* is not evidence of
    danger — the dangerous transitions are recognized by tier, not by name.

    So the default is to allow and audit, and only ``strict`` mode stops to ask.

    One case is different: the host says untrusted content proposed the action.
    That is evidence about the origin, and untrusted content has no authority
    over an action the guard cannot tell from a write. A read tool that gets
    caught by this is declared in ``tool_tiers``.
    """
    if _suggested_by_untrusted(context):
        return _tuned(
            tier_setting(context, "unknown_action_from_untrusted", Decision.DENY),
            ReasonCode.UNTRUSTED_TO_UNKNOWN_ACTION,
            "Unclassified action proposed by untrusted content; declare the "
            "tool in tool_tiers if it is harmless.",
        )
    if resolve_mode(context) == MODE_STRICT:
        return _decide(
            Decision.REQUIRE_CONFIRMATION,
            ReasonCode.UNKNOWN_ACTION_REQUIRES_CONFIRMATION,
            "Unclassified action; strict mode requires explicit confirmation.",
        )
    return _tuned(
        tier_setting(context, "unknown_action", Decision.ALLOW_WITH_WARNING),
        ReasonCode.UNKNOWN_ACTION_AUDITED,
        "Unclassified action kind; allowed and audited (not a recognized "
        "high-risk transition).",
    )


def _decide_user_scope_gates(context: GuardContext) -> Optional[GuardDecision]:
    """Gates that apply to every state-changing action, before per-tier rules.

    Returns a denial when the user scope forbids the action, else ``None`` so
    the normal per-tier logic continues.
    """
    # Gate 1: an explicit no-write scope set by the user for this turn.
    if context.no_write_scope_active:
        return _deny(
            ReasonCode.EXPLICIT_NO_WRITE_SCOPE_VIOLATION,
            "User set an explicit no-write scope this turn; state-changing "
            "action denied.",
        )

    # Gate 2: an ambiguous short confirmation ("ja", "ok", "mach das").
    # It only authorizes when it traces back to a prior explicit user order
    # for this exact action. A non-user source (document/tool/agent inference)
    # can never become authorization via a later "yes".
    if context.short_confirmation:
        if context.requested_action_from_nonuser_context:
            return _deny(
                ReasonCode.SHORT_CONFIRMATION_NONAUTHORITATIVE_SOURCE,
                "Short confirmation relays an action proposed by a "
                "non-user source; denied.",
            )
        if not context.previous_action_was_explicitly_authorized:
            return _deny(
                ReasonCode.SHORT_CONFIRMATION_NO_PRIOR_AUTH,
                "Short confirmation without a prior explicit user "
                "authorization; denied.",
            )
    return None


def _decide_self_modification(
    action: AgentAction, context: GuardContext
) -> GuardDecision:
    """Skill patch / self-improvement / procedural-rule changes.

    Never a direct ``allow``: the agent must never silently rewrite its own
    future behavior. A bare confirmation only counts when it is bound to a
    prior explicit user order (see the two-phase confirm flow in
    ``self_improvement.py``). ``require_confirmation`` is a pending intent,
    not a write grant.
    """
    # First, because the denial for a missing user order is one a host may
    # answer with an approval prompt, and no approval makes this target right.
    if any(
        outside_workspace(path, context.workspace_root)
        for path in _written_paths(action)
    ):
        return _deny(
            ReasonCode.SELF_MODIFICATION_TARGET_OUTSIDE_WORKSPACE,
            "Self-modification target lies outside the workspace root the "
            "host named; denied.",
        )
    authorized = context.user_intent_origin is UserIntentOrigin.HUMAN_EXPLICIT or (
        context.user_intent_origin is UserIntentOrigin.HUMAN_CONFIRMATION
        and context.previous_action_was_explicitly_authorized
        and not context.requested_action_from_nonuser_context
    )
    if not authorized:
        return _deny(
            ReasonCode.SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER,
            "Self-modification requires an explicit user order; agent-initiated "
            "or unauthorized self-improvement is denied.",
        )
    if not (action.target or "").strip():
        return _deny(
            ReasonCode.SELF_MODIFICATION_REQUIRES_EXPLICIT_TARGET,
            "Self-modification requires an explicit, concrete target.",
        )
    return _decide(
        Decision.REQUIRE_CONFIRMATION,
        ReasonCode.SELF_MODIFICATION_REQUIRES_CONFIRMATION,
        "Self-modification authorized in principle; requires explicit "
        "confirmation bound to this exact patch before any write.",
    )


def outside_workspace(
    target: str, root: Optional[str], *, follow_links: bool = False
) -> bool:
    """Whether ``target`` names a path outside ``root``.

    ``..`` segments, an absolute path and a ``file:`` URL are resolved before
    comparing, so ``skills/../../.bashrc`` is outside ``skills``. A relative
    target is taken relative to the root, which also keeps a target that is no
    path at all (a rule id) inside. No root means nothing to be outside of.

    By default the comparison is on the names alone and touches no file. With
    ``follow_links`` symbolic links are resolved too; that is for the moment
    right before a write, where a link inside the root may point out of it.
    """
    root = (root or "").strip()
    path = (target or "").strip()
    if not root or not path:
        return False
    if path.lower().startswith("file:"):
        path = unquote(urlsplit(path).path)
    resolve = os.path.realpath if follow_links else os.path.abspath
    try:
        base = resolve(os.path.expanduser(root))
        full = resolve(os.path.join(base, os.path.expanduser(path)))
        return os.path.commonpath([base, full]) != base
    except (OSError, ValueError):  # unreadable, or nothing in common at all
        return True


def _decide_local_read(context: GuardContext) -> GuardDecision:
    sensitivity = context.data_sensitivity
    if sensitivity is DataSensitivity.SECRET:
        return _decide(
            Decision.REQUIRE_CONFIRMATION,
            ReasonCode.SENSITIVE_PATH_READ,
            "Reading secret-class content; confirm before proceeding.",
        )
    if sensitivity is DataSensitivity.SENSITIVE:
        return _decide(
            Decision.ALLOW_WITH_WARNING,
            ReasonCode.SENSITIVE_PATH_READ,
            "Reading sensitive content; allowed and audited.",
        )
    return _tuned(
        tier_setting(context, "local_read", Decision.ALLOW),
        ReasonCode.ALLOW_LOCAL_READ,
        "Local read of non-sensitive content.",
    )


def _decide_execution(action: AgentAction, context: GuardContext) -> GuardDecision:
    if _untrusted(context):
        return _deny(
            ReasonCode.UNTRUSTED_TO_SHELL,
            "Shell/execution from untrusted content is denied.",
        )
    if _suggested_by_untrusted(context):
        return _deny(
            ReasonCode.CONFIRMATION_ORIGIN_UNTRUSTED,
            "Execution originated from untrusted content; a bare confirmation "
            "does not authorize it.",
        )
    return _trusted_origin_gate(
        action, context, "shell_from_user",
        ReasonCode.SHELL_FROM_USER_REQUIRES_CONFIRMATION,
        "Shell/execution from a trusted origin requires confirmation.",
    )


# Paths named by a patch body: the V4A headers used by apply_patch-style tools
# and the "+++ b/path" line of a unified diff.
_PATCH_PATH = re.compile(
    r"^(?:\*\*\* (?:Add|Update|Delete) File: |\*\*\* Move to: |\+\+\+ (?:b/)?)(\S.*?)\s*$",
    re.MULTILINE,
)


def _written_paths(action: AgentAction) -> List[str]:
    """The paths a file tool is about to write: its target plus any named in a
    patch body, where a multi-file patch carries no single target."""
    paths = [action.target or ""]
    texts = [action.payload] + list((action.metadata or {}).values())
    for text in texts:
        if isinstance(text, str) and ("***" in text or "+++" in text):
            paths.extend(_PATCH_PATH.findall(text))
    # `+++ /dev/null` is how a diff says "deleted", not a file it writes.
    return [path for path in paths if path and path != "/dev/null"]


def _changes_the_agent(action: AgentAction, context: GuardContext) -> bool:
    patterns = (
        context.config.self_modification_paths
        if context.config is not None
        else DEFAULT_CONFIG["self_modification_paths"]
    )
    return any(
        path_matches(path, patterns, ignore_case=True)
        for path in _written_paths(action)
    )


def _decide_local_write(action: AgentAction, context: GuardContext) -> GuardDecision:
    """A write to the local filesystem by a host file tool."""
    if _changes_the_agent(action, context):
        # A file tool pointed at a skill or at the guard's policy is the same
        # act as skill_patch, so it meets the same bar.
        return _decide_self_modification(action, context)
    if _untrusted(context) or _suggested_by_untrusted(context):
        return _deny(
            ReasonCode.UNTRUSTED_TO_LOCAL_WRITE,
            "File write requested from untrusted content is denied.",
        )
    if resolve_mode(context) == MODE_STRICT:
        # Strict asked for confirmation on these while they were unrecognized;
        # recognizing them must not make strict weaker.
        return _decide(
            Decision.REQUIRE_CONFIRMATION,
            ReasonCode.LOCAL_WRITE_REQUIRES_CONFIRMATION,
            "File write; strict mode requires explicit confirmation.",
        )
    return _tuned(
        tier_setting(context, "local_write", Decision.ALLOW_WITH_WARNING),
        ReasonCode.LOCAL_WRITE_AUDITED,
        "Local file write from a trusted origin; allowed and audited.",
    )


def _trusted_origin_gate(
    action: AgentAction,
    context: GuardContext,
    key: str,
    reason: ReasonCode,
    message: str,
) -> GuardDecision:
    """The tunable decision for a gated tier once its hard denials have passed.

    A kind the host named explicitly, or a tool the operator declared, gets the
    tier's own setting (confirmation by default). A host tool the guard only
    recognized by its name gets ``recognized_host_tool`` instead (allow and
    audit by default): the host never opted into a confirmation flow for it,
    and asking anyway is what blocked hosts' own tools in 0.2.x. That holds
    only while nothing points at danger: ``strict`` mode, an untrusted origin,
    or sensitive data put the tier's own setting back in force.
    """
    if (
        recognized_by_name_only(action, context.config)
        and resolve_mode(context) != MODE_STRICT
        and not _untrusted(context)
        and context.data_sensitivity.rank < DataSensitivity.SENSITIVE.rank
    ):
        return _tuned(
            tier_setting(context, "recognized_host_tool", Decision.ALLOW_WITH_WARNING),
            ReasonCode.HOST_TOOL_AUDITED,
            "Host tool recognized by name, trusted origin; allowed and audited.",
        )
    return _tuned(
        tier_setting(context, key, Decision.REQUIRE_CONFIRMATION), reason, message
    )


def _decide_install(action: AgentAction, context: GuardContext) -> GuardDecision:
    if _untrusted(context) or _suggested_by_untrusted(context):
        return _deny(
            ReasonCode.INSTALL_FROM_UNTRUSTED,
            "Install/update requested from untrusted content is denied.",
        )
    return _trusted_origin_gate(
        action, context, "install_from_user",
        ReasonCode.INSTALL_REQUIRES_CONFIRMATION,
        "Install/update from a trusted origin requires confirmation.",
    )


def _decide_external_write(
    action: AgentAction, context: GuardContext
) -> GuardDecision:
    if context.data_sensitivity is DataSensitivity.SECRET:
        return _deny(
            ReasonCode.SECRET_EXTERNAL_SEND,
            "External write of secret-class content is denied (exfiltration).",
        )
    if _suggested_by_untrusted(context):
        return _deny(
            ReasonCode.CONFIRMATION_ORIGIN_UNTRUSTED,
            "External write originated from untrusted content; denied.",
        )
    # The two shortcuts below skip the confirmation gate, so they are for
    # trusted origins only. Untrusted content steering a write at a local admin
    # API (Docker, Redis) or at an allowlisted host is not pre-approved.
    if not _untrusted(context):
        # An explicitly allowlisted domain is pre-approved by the operator, so
        # it does not need a per-call confirmation. It is still audited.
        if context.domain_allowlist and domain_allowed(
            action.target, context.domain_allowlist
        ):
            return _decide(
                Decision.ALLOW,
                ReasonCode.ALLOW_DEFAULT,
                "External write to an operator-allowlisted domain.",
            )
        # A write to loopback does not leave the machine, so it is not the
        # exfiltration risk this tier exists for. Gating it broke ordinary
        # local tooling (dashboards, local APIs) on every call. Secret payloads
        # are already denied above, and the secret-read chain rule still applies.
        if is_loopback_target(action.target):
            return _decide(
                Decision.ALLOW_WITH_WARNING,
                ReasonCode.ALLOW_DEFAULT,
                "Write to a local loopback address; allowed and audited.",
            )
    return _trusted_origin_gate(
        action, context, "external_write",
        ReasonCode.EXTERNAL_WRITE_REQUIRES_CONFIRMATION,
        "External write requires confirmation.",
    )


def _decide_config_change(action: AgentAction, context: GuardContext) -> GuardDecision:
    if _untrusted(context) or _suggested_by_untrusted(context):
        return _deny(
            ReasonCode.CONFIRMATION_ORIGIN_UNTRUSTED,
            "Config/profile change requested from untrusted content is denied.",
        )
    return _trusted_origin_gate(
        action, context, "config_change",
        ReasonCode.CONFIG_CHANGE_REQUIRES_CONFIRMATION,
        "Config/profile change requires confirmation.",
    )


def _decide_memory_write(action: AgentAction, context: GuardContext) -> GuardDecision:
    """A write to the agent's memory, judged by the lane it names.

    ``untrusted`` is evidence about this write: the origin of the call, what
    proposed it, or a stated source that is neither observation nor
    conversation. Without it only the privileged lanes are held back.
    """
    stated = (action.desired_memory_lane or "").strip()
    lane = read_lane(stated, context.config)
    source = read_source(action.memory_source)
    untrusted = (
        _untrusted(context)
        or _suggested_by_untrusted(context)
        or source_is_untrusted(source)
    )

    if lane in PRIVILEGED_LANES:
        if untrusted or source == CONVERSATION:
            return _deny(
                PRIVILEGED_LANES[lane],
                f"'{lane}' memory is written from direct observation only; "
                f"this write ({_source_label(source, untrusted)}) cannot "
                "promote to it. Evidence is the lane it may use.",
            )
        if source == OBSERVATION:
            return _audited(_allow(
                ReasonCode.PRIVILEGED_MEMORY_AUDITED,
                f"Observation may write '{lane}' memory; allowed and audited.",
            ))
        # Nobody said where this comes from. A plain allow here let any
        # caller that left the source out write a permission or a rule
        # without a trace.
        return _audited(_tuned(
            tier_setting(
                context, "memory_unsourced_to_privileged", Decision.REQUIRE_CONFIRMATION
            ),
            ReasonCode.PRIVILEGED_MEMORY_REQUIRES_CONFIRMATION,
            f"Write to '{lane}' memory without a stated source; that lane is "
            "written from direct observation only.",
        ))

    if lane in (NO_LANE, UNKNOWN_LANE):
        # Not presumed to be evidence: the guard cannot tell this write from
        # one to a privileged lane.
        what = f"lane '{stated}', which the guard does not know" if stated else "no lane"
        if untrusted:
            return _audited(_tuned(
                tier_setting(context, "memory_external_to_unknown_lane", Decision.DENY),
                ReasonCode.UNTRUSTED_TO_UNKNOWN_MEMORY_LANE,
                f"Memory write from an untrusted source names {what}; it "
                "cannot be told from a privileged write. Evidence is the "
                "lane it may use.",
            ))
        if resolve_mode(context) == MODE_STRICT:
            # Strict asked about a host's memory tool while it was
            # unrecognized; recognizing it must not make strict weaker.
            return _decide(
                Decision.REQUIRE_CONFIRMATION,
                ReasonCode.MEMORY_WRITE_REQUIRES_CONFIRMATION,
                f"Memory write names {what}; strict mode requires explicit "
                "confirmation.",
            )
        return _decide(
            Decision.ALLOW_WITH_WARNING,
            ReasonCode.UNKNOWN_MEMORY_LANE_AUDITED,
            f"Memory write names {what}; trusted origin, allowed and audited.",
        )

    if not untrusted:
        return _allow(ReasonCode.ALLOW_DEFAULT, f"Memory write to '{lane}' allowed.")

    if lane in PERSONAL_LANES:
        return _decide(
            Decision.REQUIRE_CONFIRMATION,
            PERSONAL_LANES[lane],
            f"Untrusted source writing {lane} memory requires confirmation.",
        )
    return _decide(
        Decision.ALLOW_WITH_WARNING,
        ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY,
        "Untrusted source writing evidence memory; allowed and audited.",
    )


def _source_label(source: str, untrusted: bool) -> str:
    if source:
        return f"source '{source}'"
    return "untrusted origin" if untrusted else "no stated source"


# --------------------------------------------------------------------------- #
# Decision constructors
# --------------------------------------------------------------------------- #


def _decide(decision: Decision, reason: ReasonCode, message: str) -> GuardDecision:
    return GuardDecision(decision=decision, reason_code=reason, message=message)


def _tuned(decision: Decision, reason: ReasonCode, message: str) -> GuardDecision:
    """Build a decision from a tunable setting.

    When an operator relaxes a gate to ``allow``, the gate's own
    ``*_REQUIRES_CONFIRMATION`` code would misreport the outcome, so a plain
    allow reports ``ALLOW_DEFAULT`` instead.
    """
    if decision is Decision.ALLOW:
        if reason.value.endswith("_REQUIRES_CONFIRMATION"):
            return _allow(
                ReasonCode.ALLOW_DEFAULT,
                f"{message} (relaxed to allow by policy configuration)",
            )
        return _allow(reason, message)
    return _decide(decision, reason, message)


def _allow(reason: ReasonCode, message: str) -> GuardDecision:
    return GuardDecision(
        decision=Decision.ALLOW,
        reason_code=reason,
        message=message,
        audit_required=False,
    )


def _audited(decision: GuardDecision) -> GuardDecision:
    """Keep the audit record also where the outcome is a plain allow."""
    decision.audit_required = True
    return decision


def _deny(reason: ReasonCode, message: str) -> GuardDecision:
    return GuardDecision(decision=Decision.DENY, reason_code=reason, message=message)

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
import os
from typing import Any, Dict, List, Optional

from . import _miniyaml
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
        "memory_external_to_authorization": "deny",
        "memory_external_to_procedural": "deny",
        "download_inspect": "allow",
        "download_then_execute_untrusted": "deny",
        "download_then_execute_user": "require_confirmation",
    },
    "sensitive_paths": [
        ".env", ".env.*", "*.pem", "*.key", "*.crt", "*.p12", "*.pfx",
        "*.kdbx", "*.sqlite", "*.db", "id_rsa", "id_rsa.*", ".ssh/", ".aws/",
        ".gcp/", ".azure/", ".kube/", ".npmrc", ".pypirc", ".netrc",
        ".git-credentials", "secrets.*", "credentials.*", "token.*", "auth.*",
        "*.log", "logs/", "backups/", "docker-compose.yml", "settings.json",
        "config.py",
    ],
    "secret_patterns": [
        r"(?i)api[_-]?key",
        r"(?i)secret[_-]?key",
        r"(?i)access[_-]?token",
        r"(?i)bearer\s+[A-Za-z0-9._-]{12,}",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        r"(?i)password\s*[:=]",
    ],
    "audit": {
        "backend": "sqlite",
        "path": "guard-audit.db",
        "jsonl_path": "guard-audit.jsonl",
    },
    "limits": {
        "max_content_chars": 20000,
        "max_history_events": 50,
    },
}


def load_config(path: Optional[str] = None) -> GuardConfig:
    """Load ``guard.yaml`` merged over built-in defaults.

    A missing file yields the defaults. A malformed file raises (fail loud):
    a security policy must never silently fall back to weaker defaults.
    """
    merged: Dict[str, Any] = _deep_copy_defaults()
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            loaded = _miniyaml.load(handle.read())
        if not isinstance(loaded, dict):
            raise ValueError("guard.yaml must be a mapping at the top level")
        for key, value in loaded.items():
            if key in ("tiers", "audit", "limits") and isinstance(value, dict):
                merged[key] = {**merged.get(key, {}), **value}
            else:
                merged[key] = value
    return GuardConfig(
        mode=merged["mode"],
        domain_allowlist=list(merged.get("domain_allowlist", [])),
        tiers=dict(merged.get("tiers", {})),
        sensitive_paths=list(merged.get("sensitive_paths", [])),
        secret_patterns=list(merged.get("secret_patterns", [])),
        audit=dict(merged.get("audit", {})),
        limits=dict(merged.get("limits", {})),
    )


def _deep_copy_defaults() -> Dict[str, Any]:
    return {
        "mode": DEFAULT_CONFIG["mode"],
        "domain_allowlist": list(DEFAULT_CONFIG["domain_allowlist"]),
        "tiers": dict(DEFAULT_CONFIG["tiers"]),
        "sensitive_paths": list(DEFAULT_CONFIG["sensitive_paths"]),
        "secret_patterns": list(DEFAULT_CONFIG["secret_patterns"]),
        "audit": dict(DEFAULT_CONFIG["audit"]),
        "limits": dict(DEFAULT_CONFIG["limits"]),
    }


# --------------------------------------------------------------------------- #
# Predicates
# --------------------------------------------------------------------------- #


def path_is_sensitive(path: str, patterns: List[str]) -> bool:
    """Glob-match a path against sensitive-path patterns.

    Patterns ending in ``/`` match a directory anywhere in the path; other
    patterns match the basename or the full normalized path.
    """
    if not path:
        return False
    normalized = path.replace("\\", "/").strip()
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


def _extract_host(target: str) -> str:
    if not target:
        return ""
    value = target.strip().lower()
    for scheme in ("http://", "https://", "ftp://", "ftps://"):
        if value.startswith(scheme):
            value = value[len(scheme):]
            break
    value = value.split("/", 1)[0]
    value = value.split("@")[-1]
    value = value.split(":", 1)[0]
    return value


def _untrusted(context: GuardContext) -> bool:
    return context.origin_trust.is_untrusted


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


def decide_action(
    action: AgentAction, tier: ActionTier, context: GuardContext
) -> GuardDecision:
    """Evaluate the deterministic hard-rule matrix for a single action."""
    if tier is ActionTier.READ_ONLY:
        return _allow(ReasonCode.ALLOW_READ_ONLY, "Read-only action; allowed.")

    if tier is ActionTier.LOCAL_READ:
        return _decide_local_read(context)

    if tier is ActionTier.EXECUTION:
        return _decide_execution(context)

    if tier is ActionTier.DOWNLOAD:
        return _decide(
            Decision.ALLOW_WITH_WARNING,
            ReasonCode.ALLOW_DOWNLOAD_INSPECT,
            "Download allowed; executing the artifact is gated separately.",
        )

    if tier is ActionTier.INSTALL:
        return _decide_install(context)

    if tier is ActionTier.EXTERNAL_WRITE:
        return _decide_external_write(context)

    if tier is ActionTier.MEMORY_WRITE:
        return _decide_memory_write(action, context)

    if tier is ActionTier.CONFIG_CHANGE:
        return _decide_config_change(context)

    if tier is ActionTier.SECRET_HANDLING:
        return _deny(
            ReasonCode.SECRET_EXTERNAL_SEND,
            "Handling/sending secret material externally is denied.",
        )

    # ActionTier.UNKNOWN and any unmapped tier -> fail safe.
    return _decide(
        Decision.REQUIRE_CONFIRMATION,
        ReasonCode.UNKNOWN_ACTION_REQUIRES_CONFIRMATION,
        "Unclassified action; requires explicit human confirmation.",
    )


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
    return _allow(ReasonCode.ALLOW_LOCAL_READ, "Local read of non-sensitive content.")


def _decide_execution(context: GuardContext) -> GuardDecision:
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
    return _decide(
        Decision.REQUIRE_CONFIRMATION,
        ReasonCode.SHELL_FROM_USER_REQUIRES_CONFIRMATION,
        "Shell/execution from a trusted origin requires confirmation.",
    )


def _decide_install(context: GuardContext) -> GuardDecision:
    if _untrusted(context) or _suggested_by_untrusted(context):
        return _deny(
            ReasonCode.INSTALL_FROM_UNTRUSTED,
            "Install/update requested from untrusted content is denied.",
        )
    return _decide(
        Decision.REQUIRE_CONFIRMATION,
        ReasonCode.INSTALL_REQUIRES_CONFIRMATION,
        "Install/update from a trusted origin requires confirmation.",
    )


def _decide_external_write(context: GuardContext) -> GuardDecision:
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
    return _decide(
        Decision.REQUIRE_CONFIRMATION,
        ReasonCode.EXTERNAL_WRITE_REQUIRES_CONFIRMATION,
        "External write requires confirmation.",
    )


def _decide_config_change(context: GuardContext) -> GuardDecision:
    if _untrusted(context) or _suggested_by_untrusted(context):
        return _deny(
            ReasonCode.CONFIRMATION_ORIGIN_UNTRUSTED,
            "Config/profile change requested from untrusted content is denied.",
        )
    return _decide(
        Decision.REQUIRE_CONFIRMATION,
        ReasonCode.CONFIG_CHANGE_REQUIRES_CONFIRMATION,
        "Config/profile change requires confirmation.",
    )


# Lanes that untrusted sources may never promote into.
_PRIVILEGED_LANES = {
    "authorization": ReasonCode.UNTRUSTED_TO_AUTH_MEMORY,
    "procedural": ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY,
}
_TRUSTED_MEMORY_SOURCES = frozenset({"observation"})


def _decide_memory_write(action: AgentAction, context: GuardContext) -> GuardDecision:
    lane = (action.desired_memory_lane or "evidence").strip().lower()
    source = (action.memory_source or "").strip().lower()
    untrusted = (
        _untrusted(context)
        or _suggested_by_untrusted(context)
        or (source != "" and source not in _TRUSTED_MEMORY_SOURCES)
    )

    if not untrusted:
        return _allow(ReasonCode.ALLOW_DEFAULT, f"Memory write to '{lane}' allowed.")

    if lane in _PRIVILEGED_LANES:
        return GuardDecision(
            decision=Decision.DENY,
            reason_code=_PRIVILEGED_LANES[lane],
            message=(
                f"Untrusted source cannot promote to '{lane}' memory; "
                "evidence only."
            ),
        )
    if lane == "identity":
        return _decide(
            Decision.REQUIRE_CONFIRMATION,
            ReasonCode.UNTRUSTED_TO_IDENTITY_MEMORY,
            "Untrusted source writing identity memory requires confirmation.",
        )
    return _decide(
        Decision.ALLOW_WITH_WARNING,
        ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY,
        f"Untrusted source quarantined to evidence (requested '{lane}').",
    )


# --------------------------------------------------------------------------- #
# Decision constructors
# --------------------------------------------------------------------------- #


def _decide(decision: Decision, reason: ReasonCode, message: str) -> GuardDecision:
    return GuardDecision(decision=decision, reason_code=reason, message=message)


def _allow(reason: ReasonCode, message: str) -> GuardDecision:
    return GuardDecision(
        decision=Decision.ALLOW,
        reason_code=reason,
        message=message,
        audit_required=False,
    )


def _deny(reason: ReasonCode, message: str) -> GuardDecision:
    return GuardDecision(decision=Decision.DENY, reason_code=reason, message=message)

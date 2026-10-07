"""Deterministic action classification: ``classify_action`` -> ``ActionTier``.

Classifying first, then deciding, keeps the policy testable: tests can assert
the tier independently of the decision. Unknown kinds fall back to
``ActionTier.UNKNOWN`` (which the policy treats as require-confirmation), so a
new, unmapped action fails safe rather than slipping through as read-only.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Optional

from .types import ActionTier, AgentAction


_REMOTE_SCHEMES = ("http://", "https://", "ftp://", "ftps://")

# kind -> tier, for kinds that map unambiguously.
_KIND_TIER = {
    "search": ActionTier.READ_ONLY,
    "web_search": ActionTier.READ_ONLY,
    "summarize": ActionTier.READ_ONLY,
    "web_fetch": ActionTier.READ_ONLY,
    "http_get": ActionTier.READ_ONLY,
    "https_get": ActionTier.READ_ONLY,
    "http_head": ActionTier.READ_ONLY,
    "http_post": ActionTier.EXTERNAL_WRITE,
    "http_put": ActionTier.EXTERNAL_WRITE,
    "http_patch": ActionTier.EXTERNAL_WRITE,
    "http_delete": ActionTier.EXTERNAL_WRITE,
    "external_write": ActionTier.EXTERNAL_WRITE,
    "api_post": ActionTier.EXTERNAL_WRITE,
    "shell": ActionTier.EXECUTION,
    "exec": ActionTier.EXECUTION,
    "run": ActionTier.EXECUTION,
    "subprocess": ActionTier.EXECUTION,
    "download": ActionTier.DOWNLOAD,
    "fetch_file": ActionTier.DOWNLOAD,
    "wget": ActionTier.DOWNLOAD,
    "install": ActionTier.INSTALL,
    "pip_install": ActionTier.INSTALL,
    "npm_install": ActionTier.INSTALL,
    "skill_install": ActionTier.INSTALL,
    "plugin_install": ActionTier.INSTALL,
    "memory_write": ActionTier.MEMORY_WRITE,
    "remember": ActionTier.MEMORY_WRITE,
    "config_change": ActionTier.CONFIG_CHANGE,
    "profile_change": ActionTier.CONFIG_CHANGE,
    "settings_write": ActionTier.CONFIG_CHANGE,
    # Self-modification: changes the agent's own future behavior. Higher-risk
    # than a normal file write, so it gets its own tier. (skill_install stays
    # INSTALL: that is a supply-chain concern, handled by the install rules.)
    "skill_patch": ActionTier.SELF_MODIFICATION,
    "skill_create": ActionTier.SELF_MODIFICATION,
    "skill_delete": ActionTier.SELF_MODIFICATION,
    "skill_edit": ActionTier.SELF_MODIFICATION,
    "skill_write": ActionTier.SELF_MODIFICATION,
    "self_improvement": ActionTier.SELF_MODIFICATION,
    "self_improvement_patch": ActionTier.SELF_MODIFICATION,
    "procedural_rule_approve": ActionTier.SELF_MODIFICATION,
    "procedural_rule_retire": ActionTier.SELF_MODIFICATION,
    "rule_approve": ActionTier.SELF_MODIFICATION,
    "read_file": ActionTier.LOCAL_READ,
    "read": ActionTier.LOCAL_READ,
    "cat": ActionTier.LOCAL_READ,
    "secret_send": ActionTier.SECRET_HANDLING,
    "exfiltrate": ActionTier.SECRET_HANDLING,
}

# HTTP methods that mutate remote state.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def classify_action(action: AgentAction) -> ActionTier:
    """Map an ``AgentAction`` to a single ``ActionTier`` deterministically."""
    kind = (action.kind or "").strip().lower()

    # Generic HTTP request: let the method decide read vs write.
    if kind in ("http", "https", "request", "http_request", "fetch"):
        return _classify_http(action)

    tier = _KIND_TIER.get(kind)
    if tier is not None:
        # A read of a remote URL is READ_ONLY; a read of a local path is LOCAL_READ.
        if tier is ActionTier.LOCAL_READ and _is_remote(action.target):
            return ActionTier.READ_ONLY
        return tier

    # Fall back to the method when the kind is unknown but a method is given.
    method = _method(action)
    if method in _WRITE_METHODS:
        return ActionTier.EXTERNAL_WRITE
    if method in _READ_METHODS:
        return ActionTier.READ_ONLY

    return ActionTier.UNKNOWN


def normalize_action(action: AgentAction) -> AgentAction:
    """Coerce host-supplied fields to the types the policy code assumes.

    Hosts forward tool arguments as they come: a JSON-object ``payload``, a
    numeric ``target``, ``metadata`` that is not a mapping. The policy calls
    string methods on these, so an unexpected type used to raise in the middle
    of an evaluation, and an evaluation that raises is not a denial. Returns a
    copy; the caller's object is left untouched.
    """
    return dataclasses.replace(
        action,
        kind=_text(action.kind),
        target=_text(action.target),
        method=_optional_text(action.method),
        payload=_optional_text(action.payload),
        desired_memory_lane=_optional_text(action.desired_memory_lane),
        memory_source=_optional_text(action.memory_source),
        metadata=action.metadata if isinstance(action.metadata, dict) else {},
    )


def _optional_text(value: Any) -> Optional[str]:
    return None if value is None else _text(value)


def _text(value: Any) -> str:
    """Render a value as scannable text (structured values as JSON)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:  # circular or otherwise unserializable
        return str(value)


def _classify_http(action: AgentAction) -> ActionTier:
    method = _method(action)
    if method in _WRITE_METHODS:
        return ActionTier.EXTERNAL_WRITE
    # Default unspecified HTTP to a read (GET-like).
    return ActionTier.READ_ONLY


def _method(action: AgentAction) -> Optional[str]:
    return action.method.strip().upper() if action.method else None


def _is_remote(target: str) -> bool:
    if not target:
        return False
    lowered = target.strip().lower()
    return lowered.startswith(_REMOTE_SCHEMES)

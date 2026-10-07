"""Deterministic action classification: ``classify_action`` -> ``ActionTier``.

Classifying first, then deciding, keeps the policy testable: tests can assert
the tier independently of the decision. A kind nobody classified is
``ActionTier.UNKNOWN``, never read-only; what the policy does with it depends
on the mode and on who proposed it.
"""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Any, Optional
from urllib.parse import urlsplit

from .host_tools import HOST_TOOL_TIER
from .types import ActionTier, AgentAction, GuardConfig


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


_GENERIC_HTTP_KINDS = ("http", "https", "request", "http_request", "fetch")
_READ_TIERS = frozenset({ActionTier.READ_ONLY, ActionTier.LOCAL_READ})

# ``mcp__files__write_file``, ``files.write_file``, ``files/write_file`` ...
_NAMESPACE_SEPARATOR = re.compile(r"__|[./:]")


def classify_action(
    action: AgentAction, config: Optional[GuardConfig] = None
) -> ActionTier:
    """Map an ``AgentAction`` to a single ``ActionTier`` deterministically.

    Precedence: a tier the operator declared for this tool (``tool_tiers``),
    the guard's own kind table, then the names real hosts give their tools.
    """
    kind = _kind(action)

    declared = _declared_tier(kind, config)
    if declared is not None:
        return declared

    # Generic HTTP request: let the method decide read vs write.
    if kind in _GENERIC_HTTP_KINDS:
        return _read_tier_for_target(_classify_http(action), action.target)

    tier = _KIND_TIER.get(kind)
    if tier is None:
        tier = _host_tool_tier(kind)
    if tier is not None:
        return _read_tier_for_target(tier, action.target)

    # For an unknown kind a write method makes it an external write. A read
    # method proves nothing: the host names the kind, but the model writes the
    # arguments, and `method: GET` on a shell tool is still a shell.
    if _method(action) in _WRITE_METHODS:
        return ActionTier.EXTERNAL_WRITE

    return ActionTier.UNKNOWN


def _read_tier_for_target(tier: ActionTier, target: str) -> ActionTier:
    """Which kind of read it is follows from where the target lives, not from
    the tool: a file read pointed at a URL reads the web, and a web fetch
    pointed at a ``file:`` URL reads the local disk (and may read a secret)."""
    if tier is ActionTier.LOCAL_READ and _is_remote(target):
        return ActionTier.READ_ONLY
    if tier is ActionTier.READ_ONLY and (target or "").strip().lower().startswith("file:"):
        return ActionTier.LOCAL_READ
    return tier


def sends_to_remote(action: AgentAction) -> bool:
    """True for an action that puts its target on the network: a request to a
    URL, or a web search (the query goes to the search provider)."""
    return _is_remote(action.target) or _kind(action) == "web_search"


def carries_data_out(action: AgentAction) -> bool:
    """True when a request to a URL has room for data besides the address: a
    query string, credentials in the URL, or a body."""
    if not _is_remote(action.target):
        return False
    if action.payload:
        return True
    try:
        parts = urlsplit(action.target.strip())
    except ValueError:
        return True
    return bool(parts.query or parts.username or parts.password)


def recognized_by_name_only(
    action: AgentAction, config: Optional[GuardConfig] = None
) -> bool:
    """True when the tier is the guard's reading of a host's tool name.

    False for a kind from the guard's own table and for a tool the operator
    declared: in both cases someone stated what the action is. The policy uses
    the difference to decide whether a confirmation gate applies.
    """
    kind = _kind(action)
    if _declared_tier(kind, config) is not None:
        return False
    if kind in _KIND_TIER or kind in _GENERIC_HTTP_KINDS:
        return False
    return _host_tool_tier(kind) is not None


def _kind(action: AgentAction) -> str:
    return (action.kind or "").strip().lower()


def _declared_tier(kind: str, config: Optional[GuardConfig]) -> Optional[ActionTier]:
    declared = config.tool_tiers.get(kind) if config and config.tool_tiers else None
    return ActionTier(declared) if declared is not None else None


def _host_tool_tier(kind: str) -> Optional[ActionTier]:
    """Tier for a host tool name, also when it carries a namespace prefix.

    A prefixed name is matched by its last segment for state-changing tools
    only. The prefix is chosen by whoever registered the tool, so it may make a
    name stricter but never vouch that ``evil__read_file`` is a plain read.
    """
    tier = HOST_TOOL_TIER.get(kind)
    if tier is not None:
        return tier
    last = _NAMESPACE_SEPARATOR.split(kind)[-1]
    if last == kind:
        return None
    tier = _KIND_TIER.get(last) or HOST_TOOL_TIER.get(last)
    return None if tier in _READ_TIERS else tier


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
    # No method but a body: that is a write, not a GET.
    if method is None and action.payload:
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

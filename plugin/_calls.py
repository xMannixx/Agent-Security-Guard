"""Reading a tool call from whatever a host passes to the hooks.

Best-effort and host-agnostic: Hermes passes ``tool_name`` and ``args``,
others pass a tool-use block, a function call or the whole call as one object.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

def _extract_untrusted_items(kwargs: Dict[str, Any]) -> List[Dict[str, Any]]:
    items = kwargs.get("untrusted_items")
    if isinstance(items, list):
        return [i for i in items if isinstance(i, dict)]
    return []

# The names tools give the thing they act on and the data they send. A secret
# file read as `filename=.env`, or a secret posted as `body=...`, went unseen
# while only `path` and `payload` were looked at. File contents (`content`) are
# left out on purpose: they stay on the machine.
_TARGET_KEYS = ("target", "url", "path", "file_path", "filename", "file")
_PAYLOAD_KEYS = ("payload", "body", "data", "json")


# How memory tools name the lane a write goes to and where the fact is from.
# Without these a host tool's `lane: authorization` never reached the lane
# rules, and the write was judged as one that names no lane.
_MEMORY_LANE_KEYS = ("desired_memory_lane", "memory_lane", "lane")
_MEMORY_SOURCE_KEYS = ("memory_source", "source")
# The model writes the arguments. It may call a fact less trustworthy than it
# looks, but "observation" from its pen is not the user's word.
_SOURCES_A_MODEL_CANNOT_VOUCH_FOR = ("observation", "conversation")


def _stated_lane(args: Dict[str, Any]) -> Any:
    """The lane a memory tool call names, or None.

    Two different lanes in one call are handed on together, which the guard
    reads as a lane it does not know: it cannot tell which one the tool uses,
    and `lane: authorization` next to `memory_lane: evidence` must not pass as
    the harmless one.
    """
    lanes: List[Any] = []
    for key in _MEMORY_LANE_KEYS:
        value = args.get(key)
        if value and value not in lanes:
            lanes.append(value)
    if len(lanes) > 1:
        return " | ".join(str(lane) for lane in lanes)
    return lanes[0] if lanes else None


def _stated_source(args: Dict[str, Any]) -> Any:
    source = _first(args, _MEMORY_SOURCE_KEYS)
    if (
        isinstance(source, str)
        and source.strip().lower() in _SOURCES_A_MODEL_CANNOT_VOUCH_FOR
    ):
        return None
    return source


def _first(args: Dict[str, Any], keys) -> Any:
    for key in keys:
        value = args.get(key)
        if value:
            return value
    return None


# The names hosts give the two halves of a tool call. Hermes passes
# `tool_name` and `args`. Others pass `name` and `input` (a model's tool-use
# block), a function's `arguments`, or the whole call as one mapping or object.
# Only the first pair was read, and a call in any other shape was not looked at.
_TOOL_NAME_KEYS = ("tool_name", "tool", "name", "function_name", "function")
_TOOL_ARGS_KEYS = (
    "args", "arguments", "input", "tool_input", "parameters", "params", "tool_args",
)
_TOOL_CALL_KEYS = ("tool_call", "tool_use", "function_call", "call", "function", "tool")
_SCALARS = (str, bytes, int, float, bool, list, tuple, set)


def _field(holder: Any, key: str) -> Any:
    """``holder[key]`` of a mapping, ``holder.key`` of an object."""
    if isinstance(holder, dict):
        return holder.get(key)
    if holder is None or isinstance(holder, _SCALARS):
        return None
    return getattr(holder, key, None)


def _tool_call(kwargs: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
    """The tool's name and its arguments, in whichever shape the host has
    them, or None when the call names no tool."""
    holders: List[Any] = [kwargs]
    for key in _TOOL_CALL_KEYS:
        value = kwargs.get(key)
        if value is not None and not isinstance(value, _SCALARS):
            holders.append(value)
            # a function call keeps name and arguments one level further in
            inner = _field(value, "function")
            if inner is not None and not isinstance(inner, _SCALARS):
                holders.append(inner)
    for holder in holders:
        for key in _TOOL_NAME_KEYS:
            name = _field(holder, key)
            if isinstance(name, str) and name.strip():
                return name, _arguments(holder) or _arguments(kwargs)
    return None


def _arguments(holder: Any) -> Dict[str, Any]:
    """Tool arguments as a mapping.

    A host that relays the model's tool call verbatim passes them as a JSON
    string; anything else that is not a mapping carries nothing usable.
    """
    for key in _TOOL_ARGS_KEYS:
        args = _field(holder, key)
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:  # malformed, or nested too deeply to parse
                args = None
        if isinstance(args, dict) and args:
            return args
    return {}


def _with_positional(positional: tuple, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Read a call made with positional arguments: a name, its arguments, or
    the whole call as one object. Named arguments are left as they are."""
    if not positional:
        return kwargs
    merged = dict(kwargs)
    for value in positional:
        if isinstance(value, str):
            merged.setdefault("tool_name", value)
        elif isinstance(value, dict) and not any(key in value for key in _TOOL_NAME_KEYS):
            merged.setdefault("args", value)
        elif value is not None and not isinstance(value, _SCALARS):
            merged.setdefault("tool_call", value)
    return merged

def _workspace_root(kwargs: Dict[str, Any]) -> Optional[str]:
    """The directory a self-modification is confined to, if the host names one."""
    root = kwargs.get("workspace_root")
    return root if isinstance(root, str) and root.strip() else None

def _enum(enum_cls, value, default):
    if not value:
        return default
    try:
        return enum_cls(value)
    except ValueError:
        return default

"""What is wrong with a policy file, said before it is applied.

``guard.yaml`` used to be taken as far as it could be read. A value the guard
could not use was replaced by something else without a word: an unknown
``mode`` by the default mode, an unknown ``audit.backend`` by no audit at all,
a pattern that does not compile by nothing, a text where a list belongs by its
single characters, a misspelled key by the built-in setting it was meant to
change. Each of these leaves the operator with a policy other than the one
they wrote, and several of them with a weaker one.

``problems`` names every such entry. ``load_config`` raises on the first call
that finds any, so a file is applied as written or not at all.

stdlib-only.
"""

from __future__ import annotations

import difflib
import re
from typing import Any, Callable, Dict, Iterable, List

from .modes import is_known_mode

STRING_LISTS = (
    "domain_allowlist", "sensitive_paths", "secret_patterns",
    "self_modification_paths", "untrusted_content_tools",
)
BOOLEANS = ("scope_from_text", "wrap_tool_results")
ON_ERROR = ("degrade", "deny_all")
#: ``none`` is how to say "no audit" on purpose.
AUDIT_BACKENDS = ("sqlite", "jsonl", "both", "none")

_TRUE_WORDS = ("true", "yes", "on")
_FALSE_WORDS = ("false", "no", "off")
# The smallest value each limit can take; 0 for the content limit means "whole".
_LIMIT_MINIMUM = {"max_content_chars": 0, "max_history_events": 1, "chain_window": 1}


def as_bool(value: Any) -> bool:
    """``true``/``false`` as the file may spell them. ``bool("no")`` is true."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUE_WORDS


def problems(
    loaded: Dict[str, Any],
    defaults: Dict[str, Any],
    decisions: Iterable[str],
    validators: Dict[str, Callable[[Any], Any]],
) -> List[str]:
    """Every entry of a loaded policy file the guard cannot apply as written.

    ``defaults`` is the built-in configuration, which defines the keys there
    are. ``decisions`` are the names a tier may be set to. ``validators`` check
    the sections with a rule of their own (``tool_tiers``, ``memory_lanes``)
    and raise ``ValueError``.
    """
    found: List[str] = []
    decisions = tuple(decisions)

    for key in loaded:
        if key not in defaults:
            found.append(f"unknown setting '{key}'{_hint(key, defaults)}")

    if "mode" in loaded and not is_known_mode(loaded["mode"]):
        found.append(
            f"mode: '{loaded['mode']}' is not a mode "
            "(monitor, autonomous-safe, strict)"
        )
    if "on_error" in loaded and str(loaded["on_error"]).strip().lower() not in ON_ERROR:
        found.append(f"on_error: '{loaded['on_error']}' is not one of {', '.join(ON_ERROR)}")

    for key in BOOLEANS:
        if key in loaded and not _is_bool(loaded[key]):
            found.append(f"{key}: expected true or false, got {loaded[key]!r}")

    for key in STRING_LISTS:
        if key in loaded:
            found.extend(_list_problems(key, loaded[key]))

    for index, pattern in enumerate(_items(loaded.get("secret_patterns"))):
        try:
            re.compile(str(pattern))
        except re.error as exc:
            found.append(f"secret_patterns[{index}]: {pattern!r} is not a valid pattern ({exc})")

    for key in ("tiers", "limits", "audit", "tool_tiers", "memory_lanes"):
        if key in loaded and not isinstance(loaded[key], dict):
            found.append(f"{key}: expected a mapping, got {_kind(loaded[key])}")

    tiers = _mapping(loaded.get("tiers"))
    for key, value in tiers.items():
        if key not in defaults["tiers"]:
            found.append(f"tiers: unknown setting '{key}'{_hint(key, defaults['tiers'])}")
        elif str(value).strip().lower() not in decisions:
            found.append(f"tiers.{key}: '{value}' is not one of {', '.join(decisions)}")

    limits = _mapping(loaded.get("limits"))
    for key, value in limits.items():
        if key not in defaults["limits"]:
            found.append(f"limits: unknown setting '{key}'{_hint(key, defaults['limits'])}")
        elif isinstance(value, bool) or not isinstance(value, int):
            found.append(f"limits.{key}: expected a whole number, got {value!r}")
        elif value < _LIMIT_MINIMUM.get(key, 0):
            found.append(f"limits.{key}: {value} is below {_LIMIT_MINIMUM.get(key, 0)}")

    audit = _mapping(loaded.get("audit"))
    for key, value in audit.items():
        if key not in defaults["audit"]:
            found.append(f"audit: unknown setting '{key}'{_hint(key, defaults['audit'])}")
        elif key == "backend" and str(value).strip().lower() not in AUDIT_BACKENDS:
            found.append(
                f"audit.backend: '{value}' is not one of {', '.join(AUDIT_BACKENDS)}"
            )
        elif key == "log_allows" and not _is_bool(value):
            found.append(f"audit.log_allows: expected true or false, got {value!r}")
        elif key in ("path", "jsonl_path") and not (isinstance(value, str) and value.strip()):
            found.append(f"audit.{key}: expected a file path, got {value!r}")

    for key, validate in validators.items():
        if isinstance(loaded.get(key), dict):
            try:
                validate(loaded[key])
            except ValueError as exc:
                found.append(str(exc))
    return found


def _list_problems(key: str, value: Any) -> List[str]:
    if not isinstance(value, list):
        return [
            f"{key}: expected a list, got {_kind(value)} "
            f"(write it as [a, b] or one '- item' per line)"
        ]
    return [
        f"{key}[{index}]: expected text, got {_kind(item)}"
        for index, item in enumerate(value)
        if isinstance(item, (list, dict, bool)) or item is None or str(item).strip() == ""
    ]


def _is_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    return isinstance(value, str) and value.strip().lower() in _TRUE_WORDS + _FALSE_WORDS


def _items(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _kind(value: Any) -> str:
    if value is None:
        return "nothing"
    if isinstance(value, bool):
        return f"{str(value).lower()}"
    if isinstance(value, str):
        return f"the text {value!r}"
    if isinstance(value, (int, float)):
        return f"the number {value}"
    return "a list" if isinstance(value, list) else "a mapping"


def _hint(key: str, known: Iterable[str]) -> str:
    close = difflib.get_close_matches(str(key), list(known), n=1, cutoff=0.75)
    return f" (did you mean '{close[0]}'?)" if close else ""

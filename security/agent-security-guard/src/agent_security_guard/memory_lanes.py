"""Memory lanes: one reading of a lane name and of a write's source.

The action policy, the sequence guard and the memory bridge each kept their own
copy of the privileged-lane list and compared the lane to it exactly. A write
to ``auth``, ``rules`` or ``system`` was therefore none of the privileged lanes
and fell through to the branch for harmless ones. All three now read the lane
here.

A name this module cannot read is not presumed harmless, and neither is a write
that names no lane: both come back as their own value, and the callers treat
them as something untrusted content may not write freely. The built-in aliases
only ever point at the stricter lanes; a host with lane names of its own
declares them in ``memory_lanes`` (guard.yaml).

stdlib-only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .types import GuardConfig, ReasonCode

EVIDENCE = "evidence"
PREFERENCE = "preference"
IDENTITY = "identity"
AUTHORIZATION = "authorization"
PROCEDURAL = "procedural"

LANES = (EVIDENCE, PREFERENCE, IDENTITY, AUTHORIZATION, PROCEDURAL)

#: The write names no lane.
NO_LANE = ""
#: The write names a lane this module cannot read.
UNKNOWN_LANE = "unknown"

#: Lanes that say what the agent may do or how it behaves. Written from direct
#: observation only.
PRIVILEGED_LANES = {
    AUTHORIZATION: ReasonCode.UNTRUSTED_TO_AUTH_MEMORY,
    PROCEDURAL: ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY,
}
#: Lanes that describe the user. An untrusted source asserting them is asked
#: about.
PERSONAL_LANES = {
    IDENTITY: ReasonCode.UNTRUSTED_TO_IDENTITY_MEMORY,
    PREFERENCE: ReasonCode.UNTRUSTED_TO_PREFERENCE_MEMORY,
}

_ALIASES = {
    "auth": AUTHORIZATION,
    "authz": AUTHORIZATION,
    "authorisation": AUTHORIZATION,
    "authorizations": AUTHORIZATION,
    "permission": AUTHORIZATION,
    "permissions": AUTHORIZATION,
    "grant": AUTHORIZATION,
    "grants": AUTHORIZATION,
    "approval": AUTHORIZATION,
    "approvals": AUTHORIZATION,
    "procedure": PROCEDURAL,
    "procedures": PROCEDURAL,
    "rule": PROCEDURAL,
    "rules": PROCEDURAL,
    "policy": PROCEDURAL,
    "policies": PROCEDURAL,
    "instruction": PROCEDURAL,
    "instructions": PROCEDURAL,
    "directive": PROCEDURAL,
    "directives": PROCEDURAL,
    "system": PROCEDURAL,
    "system_prompt": PROCEDURAL,
    "behavior": PROCEDURAL,
    "behaviour": PROCEDURAL,
    "profile": IDENTITY,
    "user_profile": IDENTITY,
    "preferences": PREFERENCE,
    "pref": PREFERENCE,
    "prefs": PREFERENCE,
}

# Anything that is not a letter or a digit separates words, so that quotes,
# brackets or an invisible character around a name do not make it another name.
_SEPARATORS = re.compile(r"[^a-z0-9]+")
_SUFFIXES = ("_lane", "_memory")

OBSERVATION = "observation"
CONVERSATION = "conversation"
#: Sources that may write the lanes describing the user.
_TRUSTED_SOURCES = frozenset({OBSERVATION, CONVERSATION})


def lane_name(name: Any) -> str:
    """A lane name in the form it is compared in: ``Auth-Lane`` -> ``auth``."""
    text = _SEPARATORS.sub("_", str(name or "").lower()).strip("_")
    for suffix in _SUFFIXES:
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    return text


def read_lane(name: Any, config: Optional[GuardConfig] = None) -> str:
    """One of ``LANES``, ``NO_LANE`` or ``UNKNOWN_LANE`` for a stated lane.

    The operator's ``memory_lanes`` are consulted before the built-in aliases.
    """
    text = lane_name(name)
    if not text:
        return NO_LANE
    if text in LANES:
        return text
    declared = config.memory_lanes.get(text) if config and config.memory_lanes else None
    if declared in LANES:
        return declared
    return _ALIASES.get(text, UNKNOWN_LANE)


def read_source(source: Any) -> str:
    return str(source or "").strip().lower()


def source_is_untrusted(source: str) -> bool:
    """A stated source that is neither observation nor conversation.

    The list is of what is trusted, so that a source nobody thought of
    (``web``, ``email``) is not trusted for lack of an entry. No stated source
    says nothing either way; the origin of the call decides then.
    """
    return bool(source) and source not in _TRUSTED_SOURCES


def validated_memory_lanes(raw: Any) -> Dict[str, str]:
    """``memory_lanes`` as {lane name: one of ``LANES``}; raises on a typo.

    The five lanes themselves cannot be redefined: mapping ``authorization``
    to ``evidence`` would switch off a denial that is not tunable.
    """
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("memory_lanes must be a mapping of lane name to lane")
    result: Dict[str, str] = {}
    for name, lane in raw.items():
        key, value = lane_name(name), str(lane).strip().lower()
        if value not in LANES:
            raise ValueError(
                f"memory_lanes.{name}: unknown lane {lane!r} "
                f"(expected one of {', '.join(LANES)})"
            )
        if key in LANES and key != value:
            raise ValueError(f"memory_lanes.{name}: a built-in lane cannot be redefined")
        if key:
            result[key] = value
    return result

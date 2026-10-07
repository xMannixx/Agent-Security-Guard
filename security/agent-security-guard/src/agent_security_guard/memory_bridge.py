"""Memory bridge: advice-only recommendations for memory writes.

This never touches the agent-memory skill. It returns a ``MemoryAdvice`` that a
caller may choose to honor, mapping the guard's trust model onto the memory
skill's Authority Lanes:

- ``external`` / ``tool`` (or untrusted origin) -> ``evidence`` only
- never ``authorization`` / ``procedural`` from untrusted sources
- ``identity`` only with observation (untrusted -> confirm, suggest evidence)

The agent-memory skill already enforces "authorization/procedural only from
observation"; this bridge lets a host get a lane-safe recommendation *before*
calling memory, without coupling the two skills.
"""

from __future__ import annotations

from typing import Optional

from .memory_lanes import (
    CONVERSATION,
    EVIDENCE,
    IDENTITY,
    OBSERVATION,
    PRIVILEGED_LANES,
    UNKNOWN_LANE,
    read_lane,
    read_source,
    source_is_untrusted,
)
from .scanner import classify_content
from .types import (
    Decision,
    GuardConfig,
    GuardContext,
    MemoryAdvice,
    ReasonCode,
    UserIntentOrigin,
)

_IDENTITY_TRUSTED_SOURCES = frozenset({OBSERVATION, CONVERSATION})


def advise_memory_write(
    content: str,
    desired_lane: str,
    source: str,
    context: Optional[GuardContext] = None,
    config: Optional[GuardConfig] = None,
) -> MemoryAdvice:
    """Return a lane-safe recommendation for a memory write (advice only)."""
    # ``lane`` is the name as the caller wrote it and what an allow hands
    # back; ``kind`` is what the guard reads it as (``auth`` is authorization).
    lane = (desired_lane or EVIDENCE).strip().lower()
    kind = read_lane(lane, config or (context.config if context else None))
    src = read_source(source)
    untrusted = _is_untrusted(src, context)
    note = _content_note(content, config)

    if kind in PRIVILEGED_LANES:
        if not untrusted and src == OBSERVATION:
            return _advice(Decision.ALLOW, ReasonCode.ALLOW_DEFAULT, lane,
                           f"Observation may write '{lane}'." + note)
        return _advice(
            Decision.DENY, PRIVILEGED_LANES[kind], EVIDENCE,
            f"Untrusted source ('{src or 'unknown'}') cannot promote to "
            f"'{lane}'; evidence only." + note,
        )

    if kind == UNKNOWN_LANE and untrusted:
        return _advice(
            Decision.DENY, ReasonCode.UNTRUSTED_TO_UNKNOWN_MEMORY_LANE, EVIDENCE,
            f"Untrusted source ('{src or 'unknown'}') names lane '{lane}', "
            "which the guard does not know; evidence only." + note,
        )

    if kind == IDENTITY:
        if not untrusted and src in _IDENTITY_TRUSTED_SOURCES:
            return _advice(Decision.ALLOW, ReasonCode.ALLOW_DEFAULT, "identity",
                           "Identity write from a trusted source." + note)
        return _advice(
            Decision.REQUIRE_CONFIRMATION, ReasonCode.UNTRUSTED_TO_IDENTITY_MEMORY,
            "evidence",
            "Identity write from an untrusted source requires confirmation; "
            "evidence is the safe lane." + note,
        )

    # evidence / preference, or a lane of the host's own from a trusted source
    if untrusted:
        return _advice(
            Decision.ALLOW_WITH_WARNING, ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY,
            "evidence",
            f"Untrusted source quarantined to evidence (requested '{lane}')." + note,
        )
    return _advice(Decision.ALLOW, ReasonCode.ALLOW_DEFAULT, lane,
                   f"Memory write to '{lane}' allowed." + note)


def _is_untrusted(source: str, context: Optional[GuardContext]) -> bool:
    if source_is_untrusted(source):
        return True
    if context is None:
        return False
    if context.origin_trust.is_untrusted:
        return True
    return context.user_intent_origin is UserIntentOrigin.UNTRUSTED_SUGGESTION


def _content_note(content: str, config: Optional[GuardConfig]) -> str:
    classification = classify_content(content or "", None, config)
    flags = []
    if classification.injection_indicators:
        flags.append("injection patterns")
    if classification.secret_indicators:
        flags.append("secret material")
    if not flags:
        return ""
    return " Warning: content contains " + " and ".join(flags) + "."


def _advice(
    decision: Decision, reason: ReasonCode, suggested_lane: str, message: str
) -> MemoryAdvice:
    return MemoryAdvice(
        decision=decision,
        reason_code=reason,
        suggested_lane=suggested_lane,
        message=message,
    )

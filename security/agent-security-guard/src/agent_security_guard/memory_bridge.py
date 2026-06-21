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

from .scanner import classify_content
from .types import (
    Decision,
    GuardConfig,
    GuardContext,
    MemoryAdvice,
    ReasonCode,
    UserIntentOrigin,
)

_PRIVILEGED_LANES = {
    "authorization": ReasonCode.UNTRUSTED_TO_AUTH_MEMORY,
    "procedural": ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY,
}
_UNTRUSTED_SOURCES = frozenset({"tool", "external", "inference"})
_IDENTITY_TRUSTED_SOURCES = frozenset({"observation", "conversation"})


def advise_memory_write(
    content: str,
    desired_lane: str,
    source: str,
    context: Optional[GuardContext] = None,
    config: Optional[GuardConfig] = None,
) -> MemoryAdvice:
    """Return a lane-safe recommendation for a memory write (advice only)."""
    lane = (desired_lane or "evidence").strip().lower()
    src = (source or "").strip().lower()
    untrusted = _is_untrusted(src, context)
    note = _content_note(content, config)

    if lane in _PRIVILEGED_LANES:
        if not untrusted and src == "observation":
            return _advice(Decision.ALLOW, ReasonCode.ALLOW_DEFAULT, lane,
                           f"Observation may write '{lane}'." + note)
        return _advice(
            Decision.DENY, _PRIVILEGED_LANES[lane], "evidence",
            f"Untrusted source ('{src or 'unknown'}') cannot promote to "
            f"'{lane}'; evidence only." + note,
        )

    if lane == "identity":
        if not untrusted and src in _IDENTITY_TRUSTED_SOURCES:
            return _advice(Decision.ALLOW, ReasonCode.ALLOW_DEFAULT, "identity",
                           "Identity write from a trusted source." + note)
        return _advice(
            Decision.REQUIRE_CONFIRMATION, ReasonCode.UNTRUSTED_TO_IDENTITY_MEMORY,
            "evidence",
            "Identity write from an untrusted source requires confirmation; "
            "evidence is the safe lane." + note,
        )

    # evidence / preference / anything else
    if untrusted:
        return _advice(
            Decision.ALLOW_WITH_WARNING, ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY,
            "evidence",
            f"Untrusted source quarantined to evidence (requested '{lane}')." + note,
        )
    return _advice(Decision.ALLOW, ReasonCode.ALLOW_DEFAULT, lane,
                   f"Memory write to '{lane}' allowed." + note)


def _is_untrusted(source: str, context: Optional[GuardContext]) -> bool:
    if source in _UNTRUSTED_SOURCES:
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

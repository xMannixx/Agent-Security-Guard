"""Reference self-improvement / skill-patch gate (two-phase, fail-closed).

This is the copyable template a host (Hermes/OpenClaw) MUST use instead of
writing ``SKILL.md`` directly. It encodes the governance contract:

- A skill patch is an ``AgentAction(kind="self_improvement_patch", target=...)``
  and goes through the guard (``GuardAdapter.guard_action`` -> ``check_action``
  + ``check_sequence``).
- ``require_confirmation`` is NOT a write grant. ``propose`` only produces a
  pending intent carrying an ``action_hash`` and writes nothing.
- A write happens only in ``confirm`` and only when ALL hold:
    1. the user explicitly confirmed this concrete patch,
    2. the confirmation is bound to the SAME ``action_hash``,
    3. ``no_write_scope_active`` is still False,
    4. ``requested_action_from_nonuser_context`` is False,
    5. the final guard check does not return ``deny``.
- Fail-closed: any guard error / unavailability, a ``deny``, or an
  ``action_hash`` mismatch results in NO write.

stdlib-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .adapter import GuardAdapter
from .audit import _action_hash
from .types import (
    AgentAction,
    Decision,
    GuardContext,
    GuardDecision,
    ReasonCode,
    UserIntentOrigin,
)

# A host-provided writer that performs the actual file write for a confirmed,
# guard-approved patch. Kept injectable so the gate itself never touches disk.
Writer = Callable[[AgentAction], None]

_SELF_IMPROVEMENT_EVENT = "self_improvement"


@dataclass
class PendingPatch:
    """A proposed-but-not-written skill patch, bound by ``action_hash``."""

    action: AgentAction
    action_hash: str
    decision: GuardDecision


@dataclass
class PatchResult:
    """Outcome of a confirm attempt. ``written`` is the only source of truth
    for whether the file was actually changed."""

    decision: GuardDecision
    written: bool
    action_hash: str


def build_patch_action(target: str, payload: Optional[str] = None) -> AgentAction:
    """Construct the canonical self-improvement action for a skill patch."""
    return AgentAction(kind="self_improvement_patch", target=target, payload=payload)


def propose(
    adapter: GuardAdapter,
    target: str,
    payload: Optional[str],
    context: GuardContext,
) -> PendingPatch:
    """Phase 1: evaluate the patch intent. Never writes.

    Returns a ``PendingPatch`` with the guard decision and an ``action_hash``
    the host must echo back on confirmation.
    """
    action = build_patch_action(target, payload)
    digest = _action_hash(action)
    try:
        decision = adapter.guard_action(
            action, context, event_type=_SELF_IMPROVEMENT_EVENT
        )
    except Exception as exc:  # fail-closed: an un-evaluable intent is denied
        decision = GuardDecision(
            decision=Decision.DENY,
            reason_code=ReasonCode.GUARD_UNAVAILABLE,
            message=f"Self-improvement guard unavailable: {exc}",
            risk_score=1.0,
        )
    return PendingPatch(action=action, action_hash=digest, decision=decision)


def confirm(
    adapter: GuardAdapter,
    pending: PendingPatch,
    confirmed_action_hash: str,
    context: GuardContext,
    writer: Writer,
) -> PatchResult:
    """Phase 2: write only on a hash-bound, guard-approved confirmation.

    The caller MUST pass a ``context`` whose flags truthfully reflect the user's
    explicit confirmation of THIS concrete patch (typically
    ``user_intent_origin=HUMAN_CONFIRMATION``,
    ``previous_action_was_explicitly_authorized=True``,
    ``requested_action_from_nonuser_context=False``). The guard still has the
    final say; this gate only writes when it does not deny.
    """
    # Condition 2: the confirmation must be bound to the exact proposed patch.
    if not confirmed_action_hash or confirmed_action_hash != pending.action_hash:
        return PatchResult(
            decision=GuardDecision(
                decision=Decision.DENY,
                reason_code=ReasonCode.SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER,
                message=(
                    "Confirmation is not bound to the proposed patch "
                    "(action_hash mismatch); no write."
                ),
            ),
            written=False,
            action_hash=pending.action_hash,
        )

    # Conditions 1, 3, 4, 5: re-run the guard for this exact action. The
    # user-scope gates enforce no-write-scope and non-user provenance; the
    # self-modification rule enforces explicit/bound authorization.
    try:
        decision = adapter.guard_action(
            pending.action, context, event_type=_SELF_IMPROVEMENT_EVENT
        )
    except Exception as exc:  # fail-closed
        return PatchResult(
            decision=GuardDecision(
                decision=Decision.DENY,
                reason_code=ReasonCode.GUARD_UNAVAILABLE,
                message=f"Self-improvement guard unavailable: {exc}",
                risk_score=1.0,
            ),
            written=False,
            action_hash=pending.action_hash,
        )

    if decision.decision is Decision.DENY:
        return PatchResult(decision=decision, written=False, action_hash=pending.action_hash)

    # Approved and bound: perform the write via the host-provided writer.
    # A writer failure is fail-closed (reported as not written).
    try:
        writer(pending.action)
    except Exception as exc:
        return PatchResult(
            decision=GuardDecision(
                decision=Decision.DENY,
                reason_code=ReasonCode.GUARD_UNAVAILABLE,
                message=f"Writer failed; patch not applied: {exc}",
                risk_score=1.0,
            ),
            written=False,
            action_hash=pending.action_hash,
        )
    return PatchResult(decision=decision, written=True, action_hash=pending.action_hash)

"""GuardAdapter: the host-facing facade tying the components together.

A host (Hermes/OpenClaw plugin, CLI, or test) uses one ``GuardAdapter`` per
session. It:

- wraps untrusted input into a safe data block (``guard_input``),
- evaluates a planned action against both the action policy and the recent
  chain, returning the stricter decision (``guard_action``),
- gives advice-only memory recommendations (``advise_memory``),

and keeps a bounded action history plus an optional audit sink.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Optional, Tuple

from .action_guard import check_action
from .actions import classify_action
from .audit import AuditLog, build_event
from .memory_bridge import advise_memory_write
from .policy import load_config, path_is_sensitive
from .scanner import classify_content, scan_input
from .sequence_guard import ActionHistory, check_sequence
from .types import (
    AgentAction,
    DataSensitivity,
    Decision,
    GuardConfig,
    GuardContext,
    GuardDecision,
    GuardReport,
    MemoryAdvice,
)
from .wrapper import wrap_untrusted


class GuardAdapter:
    """Per-session guard facade. Enforcement vs advisory is the host's call;
    this returns decisions and lets the host act on them."""

    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        history: Optional[ActionHistory] = None,
        audit: Optional[AuditLog] = None,
    ):
        self.config = config or load_config()
        max_events = int(self.config.limits.get("max_history_events", 50))
        self.history = history if history is not None else ActionHistory(max_events)
        self.audit = audit

    def guard_input(
        self,
        content: str,
        source: str,
        channel: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[GuardReport, str]:
        """Scan and wrap untrusted content. Returns (report, safe_block)."""
        report = scan_input(content, source, channel, metadata, self.config)
        return report, wrap_untrusted(report)

    def guard_action(
        self,
        action: AgentAction,
        context: GuardContext,
        *,
        event_type: str = "tool_call",
    ) -> GuardDecision:
        """Run the action policy and the sequence policy; stricter wins.

        Sensitivity is derived from the action itself (sensitive target path or
        secret-bearing payload) and merged with any caller-supplied value, so
        a host that omits ``data_sensitivity`` still gets correct
        secret-read / exfiltration handling.

        ``event_type`` lets callers tag the audit record (e.g.
        ``"self_improvement"`` for skill-patch gating) without changing the
        decision logic.
        """
        context = self._enrich_sensitivity(action, context)
        tier = classify_action(action)
        action_decision = check_action(action, context)
        sequence_decision = check_sequence(action, self.history, context)
        final = _stricter(action_decision, sequence_decision)

        self.history.record_action(action, context, final.decision)

        if self.audit is not None and (final.audit_required or final.decision is not Decision.ALLOW):
            self.audit.record(
                build_event(event_type, final, action=action, tier=tier, context=context)
            )
        return final

    def _enrich_sensitivity(
        self, action: AgentAction, context: GuardContext
    ) -> GuardContext:
        derived = context.data_sensitivity
        target = action.target or ""
        if target and path_is_sensitive(target, self.config.sensitive_paths):
            derived = derived.max(DataSensitivity.SENSITIVE)
        blob = action.payload or ""
        if blob:
            payload_class = classify_content(blob, None, self.config)
            derived = derived.max(payload_class.data_sensitivity)
        if derived is context.data_sensitivity:
            return context
        return dataclasses.replace(context, data_sensitivity=derived)

    def advise_memory(
        self,
        content: str,
        desired_lane: str,
        source: str,
        context: Optional[GuardContext] = None,
    ) -> MemoryAdvice:
        return advise_memory_write(content, desired_lane, source, context, self.config)


def _stricter(action: GuardDecision, sequence: GuardDecision) -> GuardDecision:
    """Pick the stricter decision; on a tie keep the direct action decision
    unless it is a plain allow (then surface the sequence reason)."""
    if sequence.decision.severity > action.decision.severity:
        return sequence
    if action.decision.severity > sequence.decision.severity:
        return action
    if action.decision is Decision.ALLOW and sequence.decision is not Decision.ALLOW:
        return sequence
    return action

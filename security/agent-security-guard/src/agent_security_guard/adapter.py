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
import logging
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote

from .action_guard import check_action
from .actions import classify_action, normalize_action, sends_to_remote
from .audit import AuditLog, build_event
from .memory_bridge import advise_memory_write
from .modes import MODE_SOURCE_ENV, apply_mode, mode_with_source
from .policy import load_config, path_is_sensitive
from .scanner import scan_input, secret_sensitivity
from .sequence_guard import DEFAULT_CHAIN_WINDOW, ActionHistory, check_sequence
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

logger = logging.getLogger(__name__)


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
        # Fixed here, once. Any code in the process can change the environment
        # later, and that must not switch a running guard to monitor.
        self._mode, self._mode_source = mode_with_source(self.config.mode)
        max_events = int(self.config.limits.get("max_history_events", 50))
        chain_window = int(
            self.config.limits.get("chain_window", DEFAULT_CHAIN_WINDOW)
        )
        self.history = (
            history
            if history is not None
            else ActionHistory(max_events, chain_window=chain_window)
        )
        self.audit = audit
        self.audit_failures = 0

    @property
    def mode(self) -> str:
        """The mode in force (env override wins over config), fixed at creation."""
        return self._mode

    @property
    def mode_source(self) -> str:
        """``"env"`` if AGENT_SECURITY_GUARD_MODE decided the mode, else ``"config"``."""
        return self._mode_source

    def guard_input(
        self,
        content: str,
        source: str,
        channel: str,
        metadata: Optional[Dict[str, Any]] = None,
        *,
        clip: bool = True,
    ) -> Tuple[GuardReport, str]:
        """Scan and wrap untrusted content. Returns (report, safe_block).

        ``clip=False`` keeps the content whole: for a tool result the host has
        already sized, cutting it at ``max_content_chars`` would cost the agent
        the rest of the page.
        """
        config = self.config
        if not clip:
            config = dataclasses.replace(
                config, limits={**config.limits, "max_content_chars": 0}
            )
        report = scan_input(content, source, channel, metadata, config)
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
        action = normalize_action(action)
        context = self._apply_session_policy(context)
        context = self._enrich_sensitivity(action, context)
        tier = classify_action(action, context.config)
        action_decision = check_action(action, context)
        sequence_decision = check_sequence(action, self.history, context)
        final = apply_mode(_stricter(action_decision, sequence_decision), self.mode)

        self.history.record_action(action, context, final.decision)

        if self.audit is not None and (final.audit_required or final.decision is not Decision.ALLOW):
            self._record_audit(event_type, final, action, tier, context)
        return final

    def _record_audit(self, event_type, final, action, tier, context) -> None:
        """Write the audit record; a failed write never changes the decision.

        Audit is observability. Letting the exception escape made the caller
        treat the action as "could not be evaluated", which threw away a denial
        that had already been reached.
        """
        try:
            self.audit.record(
                build_event(event_type, final, action=action, tier=tier, context=context)
            )
        except Exception as exc:
            self.audit_failures += 1
            logger.warning("audit write failed; decision stands: %s", exc)

    def _apply_session_policy(self, context: GuardContext) -> GuardContext:
        """Bind the context to this session's config and fixed mode.

        A caller that omitted ``config`` gets the adapter's config and mode:
        without this, a host configuring ``mode: monitor`` still got strict
        decisions whenever it passed a plain ``GuardContext`` (whose ``mode``
        field carries the dataclass default, not the operator's setting). A
        caller that brought its own config keeps its own mode, unless the env
        override decided the session mode, which outranks both.
        """
        if context.config is None:
            return dataclasses.replace(
                context, config=self.config, mode=self.mode, mode_resolved=True
            )
        mode = self.mode if self._mode_source == MODE_SOURCE_ENV else context.mode
        return dataclasses.replace(context, mode=mode, mode_resolved=True)

    def _enrich_sensitivity(
        self, action: AgentAction, context: GuardContext
    ) -> GuardContext:
        derived = context.data_sensitivity
        target = action.target or ""
        # A file: URL is a path with its characters possibly percent-encoded.
        path = unquote(target) if target.strip().lower().startswith("file:") else target
        if path and path_is_sensitive(path, self.config.sensitive_paths):
            derived = derived.max(DataSensitivity.SENSITIVE)
        blob = action.payload or ""
        if sends_to_remote(action):
            # A secret can leave in the address as well as in the body.
            blob = f"{unquote(target)}\n{blob}"
        if blob:
            derived = derived.max(secret_sensitivity(blob, self.config))
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

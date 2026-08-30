"""Operating modes. ``mode`` in guard.yaml is authoritative and enforced here.

Before 0.3.0 ``mode`` was a label only: the policy hardcoded every decision, so
an operator whose agent was being over-blocked had no way to loosen the guard
short of uninstalling it. That is fixed: every decision passes through
``apply_mode``, and the mode decides how much of it is actually enforced.

Modes, least to most blocking:

``monitor``
    Never blocks. Denials and confirmation prompts are downgraded to
    ``allow_with_warning``; the decision the blocking modes WOULD have made is
    preserved in ``advisory_decision`` / ``advisory_reason_code`` and audited.
    This is the safe way to introduce the guard into a live host and the panic
    switch when it over-blocks.

``autonomous-safe`` (default)
    Blocks the narrow, unambiguous danger set (untrusted -> shell/install,
    secret exfiltration, unauthorized self-modification, privileged memory
    injection). Actions the guard does not recognize are allowed and audited
    rather than blocked, because an unrecognized *tool name* is not evidence of
    danger and blocking it takes down the host's own operations.

``strict``
    Everything the policy can gate is gated, including unrecognized actions
    (require_confirmation). For hardened deployments where an unknown tool
    should stop and ask.

stdlib-only.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Optional

from .types import Decision, GuardDecision, ReasonCode

MODE_MONITOR = "monitor"
MODE_AUTONOMOUS_SAFE = "autonomous-safe"
MODE_STRICT = "strict"

KNOWN_MODES = (MODE_MONITOR, MODE_AUTONOMOUS_SAFE, MODE_STRICT)

DEFAULT_MODE = MODE_AUTONOMOUS_SAFE

#: Env var that overrides the configured mode. Lets an operator disable
#: blocking immediately, without editing files, when the guard misbehaves.
MODE_ENV_VAR = "AGENT_SECURITY_GUARD_MODE"

# Accepted aliases, so "off"/"report" do the obvious thing instead of silently
# falling back to a blocking mode.
_MODE_ALIASES = {
    "off": MODE_MONITOR,
    "observe": MODE_MONITOR,
    "report": MODE_MONITOR,
    "report-only": MODE_MONITOR,
    "advisory": MODE_MONITOR,
    "dry-run": MODE_MONITOR,
    "safe": MODE_AUTONOMOUS_SAFE,
    "autonomous_safe": MODE_AUTONOMOUS_SAFE,
    "default": MODE_AUTONOMOUS_SAFE,
    "enforce": MODE_STRICT,
    "paranoid": MODE_STRICT,
}


def normalize_mode(mode: Optional[str]) -> str:
    """Resolve a configured/env mode string to a known mode.

    An unrecognized value falls back to the default rather than raising: a typo
    in ``mode`` must not decide between "blocks everything" and "blocks
    nothing".
    """
    value = (mode or "").strip().lower()
    if value in KNOWN_MODES:
        return value
    return _MODE_ALIASES.get(value, DEFAULT_MODE)


def effective_mode(configured: Optional[str]) -> str:
    """The mode actually in force: the env override wins over the config."""
    override = os.environ.get(MODE_ENV_VAR)
    if override and override.strip():
        return normalize_mode(override)
    return normalize_mode(configured)


def is_blocking(mode: Optional[str]) -> bool:
    return normalize_mode(mode) != MODE_MONITOR


def apply_mode(decision: GuardDecision, mode: Optional[str]) -> GuardDecision:
    """Downgrade a decision to what the given mode actually enforces.

    Only ``monitor`` changes anything today: it turns every blocking outcome
    into ``allow_with_warning`` while preserving the original as advisory, so
    the audit trail still shows exactly what would have been blocked.
    """
    if normalize_mode(mode) != MODE_MONITOR:
        return decision
    if decision.decision in (Decision.ALLOW, Decision.ALLOW_WITH_WARNING):
        return decision
    return dataclasses.replace(
        decision,
        decision=Decision.ALLOW_WITH_WARNING,
        reason_code=ReasonCode.MONITOR_MODE_ADVISORY,
        message=(
            f"monitor mode: not enforced. Would have been "
            f"{decision.decision.value} ({decision.reason_code.value}): "
            f"{decision.message}"
        ),
        audit_required=True,
        advisory_decision=decision.decision,
        advisory_reason_code=decision.reason_code,
    )

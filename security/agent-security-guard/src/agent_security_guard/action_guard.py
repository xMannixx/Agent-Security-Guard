"""Public ``check_action`` entry point.

Thin by design: it classifies the action into a tier, runs the deterministic
hard-rule matrix in :mod:`policy`, and attaches a risk score. Keeping the
engine here (and sequence logic in ``sequence_guard``) prevents the action
guard from turning into a fat catch-all.

In Sprint 1 the risk score is derived deterministically from decision
severity. Sprint 2's content scanner will feed a real score in.
"""

from __future__ import annotations

from .actions import classify_action
from .policy import decide_action
from .types import AgentAction, Decision, GuardContext, GuardDecision


_RISK_BY_DECISION = {
    Decision.ALLOW: 0.0,
    Decision.ALLOW_WITH_WARNING: 0.25,
    Decision.TRANSFORM: 0.4,
    Decision.REQUIRE_CONFIRMATION: 0.6,
    Decision.DENY: 0.9,
}


def check_action(action: AgentAction, context: GuardContext) -> GuardDecision:
    """Classify and evaluate a single planned action."""
    tier = classify_action(action)
    decision = decide_action(action, tier, context)
    if decision.risk_score == 0.0:
        decision.risk_score = _RISK_BY_DECISION.get(decision.decision, 0.5)
    return decision

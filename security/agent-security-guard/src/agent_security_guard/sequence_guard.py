"""Kill-chain detection.

Single actions can each look harmless: read ``.env``, summarize, POST to an
API. The danger is the *sequence*. ``check_sequence`` keeps a bounded,
categorized history and denies dangerous chains:

- ``read secret -> ... -> external write``      (exfiltration)
- ``download -> execute``                        (untrusted: deny; user: confirm)
- ``untrusted web read -> shell``                (web instruction -> shell)
- ``untrusted web read -> authorization/proc memory`` (memory rule injection)

Intermediate read-only steps (e.g. "summarize") do not clear an earlier
secret read: the whole chain window is scanned, so laundering through a
summary still trips the rule.
"""

from __future__ import annotations

from collections import deque
from enum import Enum
from typing import Deque, List, Optional

from .actions import classify_action
from .types import (
    ActionTier,
    AgentAction,
    DataSensitivity,
    Decision,
    GuardContext,
    GuardDecision,
    HistoryEntry,
    OriginTrust,
    ReasonCode,
    UserIntentOrigin,
)


class SequenceCategory(str, Enum):
    SECRET_READ = "secret_read"
    LOCAL_READ = "local_read"
    WEB_READ = "web_read"
    READ_ONLY = "read_only"
    EXTERNAL_WRITE = "external_write"
    EXECUTION = "execution"
    DOWNLOAD = "download"
    MEMORY_WRITE = "memory_write"
    INSTALL = "install"
    CONFIG_CHANGE = "config_change"
    OTHER = "other"


def derive_category(
    tier: ActionTier,
    origin_trust: OriginTrust = OriginTrust.UNKNOWN,
    data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC,
) -> SequenceCategory:
    """Reduce a (tier, trust, sensitivity) triple to a chain category."""
    if tier is ActionTier.LOCAL_READ:
        # Any sensitive-or-higher read is secret-bearing for chain purposes
        # (a .env read is SENSITIVE, not SECRET, but must still gate exfil).
        if data_sensitivity.rank >= DataSensitivity.SENSITIVE.rank:
            return SequenceCategory.SECRET_READ
        return SequenceCategory.LOCAL_READ
    if tier is ActionTier.READ_ONLY:
        return SequenceCategory.WEB_READ if origin_trust.is_untrusted else SequenceCategory.READ_ONLY
    if tier is ActionTier.SECRET_HANDLING:
        return SequenceCategory.EXTERNAL_WRITE
    return _TIER_CATEGORY.get(tier, SequenceCategory.OTHER)


_TIER_CATEGORY = {
    ActionTier.EXTERNAL_WRITE: SequenceCategory.EXTERNAL_WRITE,
    ActionTier.EXECUTION: SequenceCategory.EXECUTION,
    ActionTier.DOWNLOAD: SequenceCategory.DOWNLOAD,
    ActionTier.MEMORY_WRITE: SequenceCategory.MEMORY_WRITE,
    ActionTier.INSTALL: SequenceCategory.INSTALL,
    ActionTier.CONFIG_CHANGE: SequenceCategory.CONFIG_CHANGE,
}


class ActionHistory:
    """A bounded, categorized log of recent actions for chain detection."""

    def __init__(self, max_events: int = 50):
        self._entries: Deque[HistoryEntry] = deque(maxlen=max(1, max_events))

    def record(self, entry: HistoryEntry) -> None:
        self._entries.append(entry)

    def record_action(
        self,
        action: AgentAction,
        context: GuardContext,
        decision: Optional[Decision] = None,
    ) -> HistoryEntry:
        entry = HistoryEntry(
            tier=classify_action(action),
            origin_trust=context.origin_trust,
            data_sensitivity=context.data_sensitivity,
            target=action.target,
            memory_lane=action.desired_memory_lane,
            chain_id=context.chain_id,
            decision=decision.value if decision else None,
        )
        self.record(entry)
        return entry

    @property
    def entries(self) -> List[HistoryEntry]:
        return list(self._entries)

    def relevant(self, chain_id: Optional[str]) -> List[HistoryEntry]:
        """Entries in the active chain (all entries if no chain_id is set)."""
        if chain_id is None:
            return list(self._entries)
        return [e for e in self._entries if e.chain_id == chain_id]

    def __len__(self) -> int:
        return len(self._entries)


_RISK_BY_DECISION = {
    Decision.ALLOW: 0.0,
    Decision.ALLOW_WITH_WARNING: 0.25,
    Decision.TRANSFORM: 0.4,
    Decision.REQUIRE_CONFIRMATION: 0.6,
    Decision.DENY: 0.9,
}

_PRIVILEGED_LANES = {
    "authorization": ReasonCode.UNTRUSTED_TO_AUTH_MEMORY,
    "procedural": ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY,
}


def check_sequence(
    action: AgentAction, history: ActionHistory, context: GuardContext
) -> GuardDecision:
    """Evaluate the action against the recent chain; strictest rule wins."""
    tier = classify_action(action)
    current = derive_category(tier, context.origin_trust, context.data_sensitivity)
    chain_id = context.chain_id or _meta_chain_id(action)
    past = history.relevant(chain_id)
    past_categories = {entry_category(e) for e in past}

    candidates: List[GuardDecision] = []

    if current is SequenceCategory.EXTERNAL_WRITE and SequenceCategory.SECRET_READ in past_categories:
        candidates.append(_deny(
            ReasonCode.SECRET_THEN_EXFIL,
            "A secret was read earlier in this chain; external write is blocked "
            "(exfiltration).",
        ))

    if current is SequenceCategory.EXECUTION and SequenceCategory.DOWNLOAD in past_categories:
        if _any_untrusted_download(past) or context.origin_trust.is_untrusted:
            candidates.append(_deny(
                ReasonCode.DOWNLOAD_THEN_EXECUTE,
                "Executing an untrusted downloaded artifact is denied.",
            ))
        else:
            candidates.append(_decide(
                Decision.REQUIRE_CONFIRMATION,
                ReasonCode.DOWNLOAD_THEN_EXECUTE,
                "Executing a downloaded artifact requires confirmation.",
            ))

    if current is SequenceCategory.EXECUTION and SequenceCategory.WEB_READ in past_categories:
        if context.user_intent_origin is UserIntentOrigin.HUMAN_EXPLICIT:
            candidates.append(_decide(
                Decision.REQUIRE_CONFIRMATION,
                ReasonCode.SHELL_FROM_USER_REQUIRES_CONFIRMATION,
                "Shell after reading web content; explicit confirmation required.",
            ))
        else:
            candidates.append(_deny(
                ReasonCode.UNTRUSTED_TO_SHELL,
                "Shell command following an untrusted web read is denied.",
            ))

    if current is SequenceCategory.MEMORY_WRITE and SequenceCategory.WEB_READ in past_categories:
        candidates.append(_memory_chain_decision(action))

    if not candidates:
        return _allow()

    strictest = max(candidates, key=lambda d: d.decision.severity)
    strictest.risk_score = _RISK_BY_DECISION.get(strictest.decision, 0.5)
    return strictest


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def entry_category(entry: HistoryEntry) -> SequenceCategory:
    return derive_category(entry.tier, entry.origin_trust, entry.data_sensitivity)


def _memory_chain_decision(action: AgentAction) -> GuardDecision:
    lane = (action.desired_memory_lane or "evidence").strip().lower()
    if lane in _PRIVILEGED_LANES:
        return _deny(
            _PRIVILEGED_LANES[lane],
            f"Untrusted web content cannot promote to '{lane}' memory.",
        )
    if lane == "identity":
        return _decide(
            Decision.REQUIRE_CONFIRMATION,
            ReasonCode.UNTRUSTED_TO_IDENTITY_MEMORY,
            "Writing identity memory after an untrusted web read needs confirmation.",
        )
    return _decide(
        Decision.ALLOW_WITH_WARNING,
        ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY,
        "Memory write after an untrusted web read is quarantined to evidence.",
    )


def _any_untrusted_download(past: List[HistoryEntry]) -> bool:
    return any(
        entry_category(e) is SequenceCategory.DOWNLOAD and e.origin_trust.is_untrusted
        for e in past
    )


def _meta_chain_id(action: AgentAction) -> Optional[str]:
    value = action.metadata.get("chain_id")
    return value if isinstance(value, str) else None


def _decide(decision: Decision, reason: ReasonCode, message: str) -> GuardDecision:
    return GuardDecision(decision=decision, reason_code=reason, message=message)


def _deny(reason: ReasonCode, message: str) -> GuardDecision:
    return GuardDecision(decision=Decision.DENY, reason_code=reason, message=message)


def _allow() -> GuardDecision:
    return GuardDecision(
        decision=Decision.ALLOW,
        reason_code=ReasonCode.ALLOW_DEFAULT,
        message="No dangerous sequence detected.",
        audit_required=False,
    )

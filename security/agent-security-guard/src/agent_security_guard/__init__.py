"""agent-security-guard: a deterministic transition policy engine.

Public surface grows per sprint. Sprint 1 exposes the policy core:
classification, the hard-rule matrix, and the type system.
"""

from __future__ import annotations

from .action_guard import check_action
from .actions import classify_action
from .adapter import GuardAdapter
from .audit import AuditLog, build_event, record_event
from .envelope import resolve_origin_trust
from .memory_bridge import advise_memory_write
from .sequence_guard import (
    ActionHistory,
    SequenceCategory,
    check_sequence,
    derive_category,
)
from .policy import (
    DEFAULT_CONFIG,
    decide_action,
    domain_allowed,
    load_config,
    path_is_sensitive,
)
from .scanner import classify_content, scan_input
from .types import (
    ActionTier,
    AgentAction,
    ContentClassification,
    DataSensitivity,
    Decision,
    GuardConfig,
    GuardContext,
    GuardDecision,
    GuardEvent,
    GuardReport,
    HistoryEntry,
    MemoryAdvice,
    OriginTrust,
    ReasonCode,
    UntrustedEnvelope,
    UserIntentOrigin,
)
from .wrapper import wrap_untrusted

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # engine
    "check_action",
    "classify_action",
    "decide_action",
    "load_config",
    "domain_allowed",
    "path_is_sensitive",
    "DEFAULT_CONFIG",
    # input hygiene
    "scan_input",
    "classify_content",
    "wrap_untrusted",
    "resolve_origin_trust",
    # sequence + audit
    "check_sequence",
    "ActionHistory",
    "SequenceCategory",
    "derive_category",
    "AuditLog",
    "record_event",
    "build_event",
    # bridge + adapter
    "advise_memory_write",
    "GuardAdapter",
    # enums
    "Decision",
    "ReasonCode",
    "ActionTier",
    "OriginTrust",
    "DataSensitivity",
    "UserIntentOrigin",
    # dataclasses
    "GuardConfig",
    "GuardContext",
    "AgentAction",
    "GuardDecision",
    "GuardReport",
    "UntrustedEnvelope",
    "ContentClassification",
    "MemoryAdvice",
    "GuardEvent",
    "HistoryEntry",
]

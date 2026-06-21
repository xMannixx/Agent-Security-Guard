"""Core types for agent-security-guard.

Everything the policy engine speaks is defined here: the decision/reason
enums, the two independent trust/sensitivity axes, action tiers, and the
dataclasses that flow through ``scan_input`` / ``check_action`` /
``check_sequence`` / ``advise_memory_write`` / ``record_event``.

stdlib-only. String-valued enums so values serialize cleanly to JSON/SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class Decision(str, Enum):
    """The five possible outcomes of a guard evaluation, ordered by severity."""

    ALLOW = "allow"
    ALLOW_WITH_WARNING = "allow_with_warning"
    TRANSFORM = "transform"
    REQUIRE_CONFIRMATION = "require_confirmation"
    DENY = "deny"

    @property
    def severity(self) -> int:
        return _DECISION_SEVERITY[self]

    def escalate(self, other: "Decision") -> "Decision":
        """Return the stricter of two decisions (higher severity wins)."""
        return self if self.severity >= other.severity else other


_DECISION_SEVERITY: Dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.ALLOW_WITH_WARNING: 1,
    Decision.TRANSFORM: 2,
    Decision.REQUIRE_CONFIRMATION: 3,
    Decision.DENY: 4,
}


class ReasonCode(str, Enum):
    """Machine-readable reason for a decision. Never a free string."""

    # allow / informational
    ALLOW_READ_ONLY = "ALLOW_READ_ONLY"
    ALLOW_LOCAL_READ = "ALLOW_LOCAL_READ"
    ALLOW_DEFAULT = "ALLOW_DEFAULT"
    ALLOW_DOWNLOAD_INSPECT = "ALLOW_DOWNLOAD_INSPECT"

    # untrusted -> action
    UNTRUSTED_TO_SHELL = "UNTRUSTED_TO_SHELL"
    SHELL_FROM_USER_REQUIRES_CONFIRMATION = "SHELL_FROM_USER_REQUIRES_CONFIRMATION"

    # secrets / exfiltration
    SECRET_THEN_EXFIL = "SECRET_THEN_EXFIL"
    SENSITIVE_PATH_READ = "SENSITIVE_PATH_READ"
    SECRET_EXTERNAL_SEND = "SECRET_EXTERNAL_SEND"

    # memory bridge
    UNTRUSTED_TO_AUTH_MEMORY = "UNTRUSTED_TO_AUTH_MEMORY"
    UNTRUSTED_TO_PROCEDURAL_MEMORY = "UNTRUSTED_TO_PROCEDURAL_MEMORY"
    UNTRUSTED_TO_IDENTITY_MEMORY = "UNTRUSTED_TO_IDENTITY_MEMORY"
    UNTRUSTED_TO_EVIDENCE_MEMORY = "UNTRUSTED_TO_EVIDENCE_MEMORY"

    # downloads
    DOWNLOAD_THEN_EXECUTE = "DOWNLOAD_THEN_EXECUTE"

    # external writes
    EXTERNAL_WRITE_REQUIRES_CONFIRMATION = "EXTERNAL_WRITE_REQUIRES_CONFIRMATION"

    # supply chain
    INSTALL_FROM_UNTRUSTED = "INSTALL_FROM_UNTRUSTED"
    INSTALL_REQUIRES_CONFIRMATION = "INSTALL_REQUIRES_CONFIRMATION"

    # config / profile
    CONFIG_CHANGE_REQUIRES_CONFIRMATION = "CONFIG_CHANGE_REQUIRES_CONFIRMATION"

    # input hygiene
    BOUNDARY_WRAP_REQUIRED = "BOUNDARY_WRAP_REQUIRED"

    # confirmation provenance
    CONFIRMATION_ORIGIN_UNTRUSTED = "CONFIRMATION_ORIGIN_UNTRUSTED"

    # fallbacks
    UNKNOWN_ACTION_REQUIRES_CONFIRMATION = "UNKNOWN_ACTION_REQUIRES_CONFIRMATION"
    GUARD_UNAVAILABLE = "GUARD_UNAVAILABLE"


class ActionTier(str, Enum):
    """What kind of transition an action represents."""

    READ_ONLY = "read_only"
    LOCAL_READ = "local_read"
    MEMORY_WRITE = "memory_write"
    EXTERNAL_WRITE = "external_write"
    EXECUTION = "execution"
    DOWNLOAD = "download"
    INSTALL = "install"
    CONFIG_CHANGE = "config_change"
    SECRET_HANDLING = "secret_handling"
    UNKNOWN = "unknown"


class OriginTrust(str, Enum):
    """May this source give instructions? Higher rank = more trusted.

    ``trusted_tool_output`` (e.g. a local calculator) ranks with
    ``local_project``; generic/unknown ``tool_output`` is treated as untrusted
    for action decisions (fail safe). Web/document tool payloads should be
    classified as ``external_web`` / ``external_document`` by their source kind.
    """

    TRUSTED_USER = "trusted_user"
    LOCAL_PROJECT = "local_project"
    TRUSTED_TOOL_OUTPUT = "trusted_tool_output"
    TOOL_OUTPUT = "tool_output"
    EXTERNAL_WEB = "external_web"
    EXTERNAL_DOCUMENT = "external_document"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return _ORIGIN_TRUST_RANK[self]

    @property
    def is_trusted(self) -> bool:
        """Trusted enough to originate a privileged action."""
        return self in _TRUSTED_ORIGINS

    @property
    def is_untrusted(self) -> bool:
        return not self.is_trusted


_ORIGIN_TRUST_RANK: Dict[OriginTrust, int] = {
    OriginTrust.TRUSTED_USER: 5,
    OriginTrust.LOCAL_PROJECT: 4,
    OriginTrust.TRUSTED_TOOL_OUTPUT: 4,
    OriginTrust.TOOL_OUTPUT: 2,
    OriginTrust.EXTERNAL_WEB: 1,
    OriginTrust.EXTERNAL_DOCUMENT: 1,
    OriginTrust.UNKNOWN: 0,
}

_TRUSTED_ORIGINS = frozenset(
    {
        OriginTrust.TRUSTED_USER,
        OriginTrust.LOCAL_PROJECT,
        OriginTrust.TRUSTED_TOOL_OUTPUT,
    }
)


class DataSensitivity(str, Enum):
    """How dangerous is this content if it leaks? Higher rank = more sensitive."""

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    SECRET = "secret"

    @property
    def rank(self) -> int:
        return _DATA_SENSITIVITY_RANK[self]

    def max(self, other: "DataSensitivity") -> "DataSensitivity":
        return self if self.rank >= other.rank else other


_DATA_SENSITIVITY_RANK: Dict[DataSensitivity, int] = {
    DataSensitivity.PUBLIC: 0,
    DataSensitivity.INTERNAL: 1,
    DataSensitivity.SENSITIVE: 2,
    DataSensitivity.SECRET: 3,
}


class UserIntentOrigin(str, Enum):
    """Where the *intent* to run an action came from.

    This is the backbone of the confirmation-origin check: a bare "yes" to a
    suggestion that originated in untrusted content is NOT a human-issued
    action.
    """

    HUMAN_EXPLICIT = "human_explicit"          # user issued the exact action
    HUMAN_CONFIRMATION = "human_confirmation"   # user said "yes" to a suggestion
    UNTRUSTED_SUGGESTION = "untrusted_suggestion"  # idea came from web/tool content
    AGENT_INITIATED = "agent_initiated"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class GuardConfig:
    """Resolved policy configuration (from ``guard.yaml`` merged over defaults)."""

    mode: str = "autonomous-safe"
    domain_allowlist: List[str] = field(default_factory=list)
    tiers: Dict[str, str] = field(default_factory=dict)
    sensitive_paths: List[str] = field(default_factory=list)
    secret_patterns: List[str] = field(default_factory=list)
    audit: Dict[str, Any] = field(default_factory=dict)
    limits: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentAction:
    """A planned action the agent wants to take, before it executes."""

    kind: str                                   # e.g. http_get, shell, read_file
    target: str = ""                            # url / path / command
    method: Optional[str] = None                # GET / POST / ...
    payload: Optional[str] = None
    desired_memory_lane: Optional[str] = None   # identity/preference/evidence/...
    memory_source: Optional[str] = None         # observation/conversation/tool/...
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardEvent:
    """An audit record. Mirrors the SQLite ``events`` schema."""

    ts: str
    event_type: str
    decision: str
    reason_code: str
    action_tier: Optional[str] = None
    source: Optional[str] = None
    channel: Optional[str] = None
    origin_trust: Optional[str] = None
    data_sensitivity: Optional[str] = None
    input_hash: Optional[str] = None
    action_hash: Optional[str] = None
    chain_id: Optional[str] = None
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "event_type": self.event_type,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "action_tier": self.action_tier,
            "source": self.source,
            "channel": self.channel,
            "origin_trust": self.origin_trust,
            "data_sensitivity": self.data_sensitivity,
            "input_hash": self.input_hash,
            "action_hash": self.action_hash,
            "chain_id": self.chain_id,
            "message": self.message,
        }


@dataclass
class HistoryEntry:
    """A past action, categorized for kill-chain detection."""

    tier: ActionTier
    origin_trust: OriginTrust = OriginTrust.UNKNOWN
    data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC
    target: str = ""
    memory_lane: Optional[str] = None
    chain_id: Optional[str] = None
    timestamp: Optional[str] = None
    decision: Optional[str] = None


@dataclass
class GuardContext:
    """Central container passed to ``check_action`` / ``check_sequence``."""

    mode: str = "autonomous-safe"
    origin_trust: OriginTrust = OriginTrust.UNKNOWN
    data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC
    user_intent_origin: UserIntentOrigin = UserIntentOrigin.UNKNOWN
    current_channel: str = ""
    chain_id: Optional[str] = None
    workspace_root: Optional[str] = None
    domain_allowlist: List[str] = field(default_factory=list)
    recent_events: List["GuardEvent"] = field(default_factory=list)
    config: Optional[GuardConfig] = None


@dataclass
class ContentClassification:
    """Result of ``classify_content`` (full implementation lands in Sprint 2)."""

    origin_trust: OriginTrust = OriginTrust.UNKNOWN
    data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC
    injection_indicators: List[str] = field(default_factory=list)
    secret_indicators: List[str] = field(default_factory=list)
    executable_indicators: List[str] = field(default_factory=list)
    externality: bool = False


@dataclass
class UntrustedEnvelope:
    """Provenance container for any content that enters the agent.

    Trust ("may this give instructions?") and sensitivity ("how bad if it
    leaks?") are stored separately and never collapsed. ``source_kind`` is what
    lets tool output inherit its payload origin (a web-fetch tool's output is
    ``external_web``, not trusted tool knowledge).
    """

    source: str
    channel: str
    source_kind: str
    origin_trust: OriginTrust
    data_sensitivity: DataSensitivity
    content_hash: str
    length: int
    timestamp: str
    url: Optional[str] = None
    content_type: Optional[str] = None
    injection_indicators: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "channel": self.channel,
            "source_kind": self.source_kind,
            "origin_trust": self.origin_trust.value,
            "data_sensitivity": self.data_sensitivity.value,
            "content_hash": self.content_hash,
            "length": self.length,
            "timestamp": self.timestamp,
            "url": self.url,
            "content_type": self.content_type,
            "injection_indicators": list(self.injection_indicators),
            "risk_score": self.risk_score,
        }


@dataclass
class GuardReport:
    """Result of ``scan_input``: a provenance envelope, the content
    classification, and the (clipped) content the wrapper will render."""

    envelope: UntrustedEnvelope
    classification: ContentClassification
    content: str = ""
    truncated: bool = False

    @property
    def source(self) -> str:
        return self.envelope.source

    @property
    def channel(self) -> str:
        return self.envelope.channel

    @property
    def content_hash(self) -> str:
        return self.envelope.content_hash

    @property
    def length(self) -> int:
        return self.envelope.length

    @property
    def content_type(self) -> Optional[str]:
        return self.envelope.content_type

    @property
    def risk_score(self) -> float:
        return self.envelope.risk_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "classification": {
                "origin_trust": self.classification.origin_trust.value,
                "data_sensitivity": self.classification.data_sensitivity.value,
                "injection_indicators": list(self.classification.injection_indicators),
                "secret_indicators": list(self.classification.secret_indicators),
                "executable_indicators": list(self.classification.executable_indicators),
                "externality": self.classification.externality,
            },
            "truncated": self.truncated,
        }


@dataclass
class GuardDecision:
    """Machine-readable outcome of a guard evaluation."""

    decision: Decision
    reason_code: ReasonCode
    message: str = ""
    transformed_action: Optional[AgentAction] = None
    audit_required: bool = True
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason_code": self.reason_code.value,
            "message": self.message,
            "transformed_action": (
                self.transformed_action.__dict__
                if self.transformed_action is not None
                else None
            ),
            "audit_required": self.audit_required,
            "risk_score": self.risk_score,
        }


@dataclass
class MemoryAdvice:
    """Advice-only recommendation for a memory write. Never mutates memory."""

    decision: Decision
    reason_code: ReasonCode
    suggested_lane: Optional[str] = None
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason_code": self.reason_code.value,
            "suggested_lane": self.suggested_lane,
            "message": self.message,
        }

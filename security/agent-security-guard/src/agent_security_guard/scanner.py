"""Content scanning: ``classify_content`` and ``scan_input``.

``classify_content`` resolves the two axes (origin trust, data sensitivity) and
the indicator lists. ``scan_input`` wraps that into a provenance ``GuardReport``
(with an ``UntrustedEnvelope``) and a deterministic, secondary risk score.

The risk score is for logging/prioritization. It never overrides a hard rule.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Pattern

from .envelope import resolve_origin_trust
from .patterns import (
    EXECUTABLE_PATTERNS,
    INJECTION_PATTERNS,
    compile_patterns,
    scan_patterns,
)
from .policy import load_config, path_is_sensitive
from .types import (
    ContentClassification,
    DataSensitivity,
    GuardConfig,
    GuardReport,
    OriginTrust,
    UntrustedEnvelope,
)


def classify_content(
    content: str,
    metadata: Optional[Dict[str, Any]] = None,
    config: Optional[GuardConfig] = None,
) -> ContentClassification:
    """Classify content along origin-trust and data-sensitivity axes.

    ``metadata`` may carry: ``source``, ``channel``, ``source_kind``,
    ``path``/``target``/``url``, ``content_type``.
    """
    metadata = metadata or {}
    config = config or load_config()

    origin_trust = resolve_origin_trust(
        source=metadata.get("source"),
        channel=metadata.get("channel"),
        source_kind=metadata.get("source_kind"),
    )

    injection = scan_patterns(content, INJECTION_PATTERNS)
    executable = scan_patterns(content, EXECUTABLE_PATTERNS)
    secret = _scan_secrets(content, config)

    sensitivity = _resolve_sensitivity(metadata, secret, config)

    return ContentClassification(
        origin_trust=origin_trust,
        data_sensitivity=sensitivity,
        injection_indicators=injection,
        secret_indicators=secret,
        executable_indicators=executable,
        externality=origin_trust.is_untrusted,
    )


def scan_input(
    content: str,
    source: str,
    channel: str,
    metadata: Optional[Dict[str, Any]] = None,
    config: Optional[GuardConfig] = None,
) -> GuardReport:
    """Scan content and build a provenance ``GuardReport``."""
    metadata = dict(metadata or {})
    metadata.setdefault("source", source)
    metadata.setdefault("channel", channel)
    config = config or load_config()

    content = content or ""
    classification = classify_content(content, metadata, config)
    risk = _risk_score(classification)

    max_chars = int(config.limits.get("max_content_chars", 20000))
    clipped, truncated = _clip(content, max_chars)

    envelope = UntrustedEnvelope(
        source=source,
        channel=channel,
        source_kind=str(metadata.get("source_kind") or ""),
        origin_trust=classification.origin_trust,
        data_sensitivity=classification.data_sensitivity,
        content_hash=_sha256(content),
        length=len(content),
        timestamp=datetime.now(timezone.utc).isoformat(),
        url=_first(metadata, ("url", "target", "path")),
        content_type=metadata.get("content_type"),
        injection_indicators=list(classification.injection_indicators),
        risk_score=risk,
    )

    return GuardReport(
        envelope=envelope,
        classification=classification,
        content=clipped,
        truncated=truncated,
    )


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _scan_secrets(content: str, config: GuardConfig) -> List[str]:
    compiled: List[Tuple[str, Pattern]] = compile_patterns(config.secret_patterns)
    return scan_patterns(content, compiled)


def _resolve_sensitivity(
    metadata: Dict[str, Any], secret_indicators: List[str], config: GuardConfig
) -> DataSensitivity:
    # Content-level secrets dominate: secrets hide in harmless-looking files.
    if secret_indicators:
        return DataSensitivity.SECRET
    path = _first(metadata, ("path", "target", "url"))
    if path and path_is_sensitive(path, config.sensitive_paths):
        return DataSensitivity.SENSITIVE
    return DataSensitivity.PUBLIC


def _risk_score(classification: ContentClassification) -> float:
    """Deterministic, bounded risk score in [0, 1]. Secondary signal only."""
    score = 0.0
    if classification.injection_indicators:
        score += 0.35 + 0.03 * (len(classification.injection_indicators) - 1)
    if classification.executable_indicators:
        score += 0.3 + 0.03 * (len(classification.executable_indicators) - 1)
    if classification.secret_indicators:
        score += 0.35
    if classification.externality:
        score += 0.1
    return round(min(score, 1.0), 4)


def _clip(content: str, max_chars: int) -> Tuple[str, bool]:
    if max_chars <= 0 or len(content) <= max_chars:
        return content, False
    return content[:max_chars], True


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _first(metadata: Dict[str, Any], keys: Tuple[str, ...]) -> Optional[str]:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None

"""Origin-trust resolution: tool output inherits its payload origin.

The channel alone is not enough. A "tool" that fetched a web page produces
``external_web`` content; a local grep produces ``local_project`` content; a
calculator produces ``trusted_tool_output``. ``resolve_origin_trust`` reads an
explicit ``source_kind`` first, then falls back to source/channel, and fails
safe to ``UNKNOWN`` (which the policy treats as untrusted).
"""

from __future__ import annotations

from typing import Optional

from .types import OriginTrust


# Canonical mapping from a source_kind / source / channel label to OriginTrust.
_TRUST_BY_LABEL = {
    # human
    "user": OriginTrust.TRUSTED_USER,
    "trusted_user": OriginTrust.TRUSTED_USER,
    "human": OriginTrust.TRUSTED_USER,
    "operator": OriginTrust.TRUSTED_USER,
    # local project
    "local_project": OriginTrust.LOCAL_PROJECT,
    "project": OriginTrust.LOCAL_PROJECT,
    "project_file": OriginTrust.LOCAL_PROJECT,
    "workspace": OriginTrust.LOCAL_PROJECT,
    "repo": OriginTrust.LOCAL_PROJECT,
    "grep": OriginTrust.LOCAL_PROJECT,
    "local_read": OriginTrust.LOCAL_PROJECT,
    "filesystem": OriginTrust.LOCAL_PROJECT,
    # trusted local tools (deterministic, no external payload)
    "calculator": OriginTrust.TRUSTED_TOOL_OUTPUT,
    "computation": OriginTrust.TRUSTED_TOOL_OUTPUT,
    "math": OriginTrust.TRUSTED_TOOL_OUTPUT,
    "trusted_tool": OriginTrust.TRUSTED_TOOL_OUTPUT,
    # web
    "web": OriginTrust.EXTERNAL_WEB,
    "web_fetch": OriginTrust.EXTERNAL_WEB,
    "webpage": OriginTrust.EXTERNAL_WEB,
    "browser": OriginTrust.EXTERNAL_WEB,
    "http": OriginTrust.EXTERNAL_WEB,
    "https": OriginTrust.EXTERNAL_WEB,
    "url": OriginTrust.EXTERNAL_WEB,
    "search_result": OriginTrust.EXTERNAL_WEB,
    "scrape": OriginTrust.EXTERNAL_WEB,
    # external documents / messages
    "email": OriginTrust.EXTERNAL_DOCUMENT,
    "message": OriginTrust.EXTERNAL_DOCUMENT,
    "document": OriginTrust.EXTERNAL_DOCUMENT,
    "pdf": OriginTrust.EXTERNAL_DOCUMENT,
    "attachment": OriginTrust.EXTERNAL_DOCUMENT,
    "dm": OriginTrust.EXTERNAL_DOCUMENT,
    "external_document": OriginTrust.EXTERNAL_DOCUMENT,
    # generic / unknown tool output (fail safe -> untrusted)
    "tool": OriginTrust.TOOL_OUTPUT,
    "tool_output": OriginTrust.TOOL_OUTPUT,
    "plugin": OriginTrust.TOOL_OUTPUT,
    "mcp": OriginTrust.TOOL_OUTPUT,
}


def resolve_origin_trust(
    source: Optional[str] = None,
    channel: Optional[str] = None,
    source_kind: Optional[str] = None,
) -> OriginTrust:
    """Resolve OriginTrust, preferring the explicit ``source_kind`` signal."""
    for label in (source_kind, source, channel):
        trust = _lookup(label)
        if trust is not None:
            return trust
    return OriginTrust.UNKNOWN


def _lookup(label: Optional[str]) -> Optional[OriginTrust]:
    if not label:
        return None
    return _TRUST_BY_LABEL.get(label.strip().lower())

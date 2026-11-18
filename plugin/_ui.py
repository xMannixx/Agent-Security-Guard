"""What the Desktop page shows, read from the guard's audit trail.

Read only. Nothing here changes the policy, the mode or the trail, and nothing
here answers an approval: those stay with the person, in Hermes's own prompt.
The trail holds the tool's name, the decision and its reason, never a tool's
arguments, so neither does anything shown from it.

``dashboard/plugin_api.py`` serves these functions to the Desktop page. Each
takes the guard package and its loaded configuration, so it reads the same
trail the hooks write.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ASKED = "asked"
BLOCKED = "blocked"
ALLOWED = "allowed"
# A change of mode made by the person, not a decision about a tool call.
MODE = "mode"

# The one denial that only lacks the user's order. Hermes asks the person
# about it when nothing untrusted proposed the call (``_decisions``).
_NEEDS_USER_ORDER = frozenset({"SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER"})
_UNTRUSTED_ORIGINS = frozenset({"untrusted", "unknown"})

# How far back the page reads. The trail itself is never cut.
MAX_READ = 5000
MAX_LIST = 200


def category(record: Dict[str, Any]) -> str:
    """``asked``, ``blocked`` or ``allowed``: what the person saw of a decision;
    ``mode`` for a change of mode."""
    if record.get("event_type") == "mode_change":
        return MODE
    decision = str(record.get("decision") or "")
    if decision == "require_confirmation":
        return ASKED
    if decision in ("deny", "transform"):
        reason = str(record.get("reason_code") or "")
        origin = str(record.get("origin_trust") or "")
        if reason in _NEEDS_USER_ORDER and origin not in _UNTRUSTED_ORIGINS:
            return ASKED
        return BLOCKED
    return ALLOWED


def when(record: Dict[str, Any]) -> Optional[datetime]:
    """The record's time, timezone-aware, or None if it has none readable."""
    try:
        stamp = datetime.fromisoformat(str(record.get("ts") or ""))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def open_audit(package, config):
    """The guard's audit trail, or None when there is none yet.

    The paths are worked out exactly as the guard does. Reading must not be
    what creates the trail, so an absent file is reported as no trail.
    """
    paths = package.AuditLog(config=config, backend="jsonl")  # touches no file
    backend = str(dict(config.audit or {}).get("backend") or "sqlite").strip().lower()
    if backend == "none":
        return None
    if backend in ("sqlite", "both"):
        present = paths.path == ":memory:" or os.path.isfile(paths.path)
    else:
        present = os.path.isfile(paths.jsonl_path)
    if not present:
        return None
    return package.AuditLog(config=config)


def _read(package, config, limit: int) -> List[Dict[str, Any]]:
    audit = open_audit(package, config)
    if audit is None:
        return []
    try:
        return audit.last(limit)
    finally:
        audit.close()


def _brings_outside_content(package, config, tool: str) -> bool:
    try:
        action = package.normalize_action(package.AgentAction(kind=tool))
        return bool(package.brings_untrusted_content(action, config))
    except Exception:
        return False


def status(package, config, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The mode, where the trail is, and what was asked, blocked and allowed today."""
    now = (now or datetime.now(timezone.utc)).astimezone()
    mode, mode_source = package.modes.mode_with_source(getattr(config, "mode", None))
    records = _read(package, config, MAX_READ)
    today = {ASKED: 0, BLOCKED: 0, ALLOWED: 0}
    for record in records:
        stamp = when(record)
        kind = category(record)
        if kind in today and stamp is not None and stamp.astimezone().date() == now.date():
            today[kind] += 1
    audit_cfg = dict(config.audit or {})
    return {
        "version": getattr(package, "__version__", None),
        "mode": mode,
        "mode_source": mode_source,
        "audit_backend": str(audit_cfg.get("backend") or "sqlite").strip().lower(),
        "today": today,
        "last_decision": records[0].get("ts") if records else None,
    }


def decisions(
    package, config, limit: int = 50, attention_only: bool = True
) -> List[Dict[str, Any]]:
    """The newest decisions, newest first.

    ``attention_only`` keeps those the person saw: asked about or blocked.
    Each says which tool brought outside content into the same turn before it,
    if one did; for a question after a web read, that is the why.
    """
    limit = max(1, min(int(limit), MAX_LIST))
    records = _read(package, config, MAX_READ)
    # Oldest first, to know for each record what came before it in its turn.
    outside_before: Dict[int, Optional[str]] = {}
    last_outside: Dict[str, str] = {}
    outside_cache: Dict[str, bool] = {}
    for index in range(len(records) - 1, -1, -1):
        record = records[index]
        chain = record.get("chain_id")
        tool = str(record.get("tool") or "")
        outside_before[index] = last_outside.get(chain) if chain else None
        if chain and tool:
            if tool not in outside_cache:
                outside_cache[tool] = _brings_outside_content(package, config, tool)
            if outside_cache[tool]:
                last_outside[chain] = tool
    shown: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        kind = category(record)
        if attention_only and kind == ALLOWED:
            continue
        shown.append({
            "ts": record.get("ts"),
            "tool": record.get("tool"),
            "category": kind,
            "decision": record.get("decision"),
            "reason_code": record.get("reason_code"),
            "message": record.get("message"),
            "tier": record.get("action_tier"),
            "after_outside_tool": outside_before.get(index),
        })
        if len(shown) >= limit:
            break
    return shown


def verify(package, config) -> Dict[str, Any]:
    """Walk the trail's hash chain: whether a record was changed, removed or added."""
    audit = open_audit(package, config)
    if audit is None:
        return {"ok": True, "records": 0, "unchained": 0, "head": "", "problem": "", "present": False}
    try:
        result = audit.verify().to_dict()
    finally:
        audit.close()
    result["present"] = True
    return result

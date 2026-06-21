"""Audit logging: ``record_event`` over a SQLite (default) or JSONL backend.

The schema is fixed up front so chains stay reconstructable. ``chain_id`` links
events that belong to the same task/sequence; ``audit --last N`` reads them back
newest-first.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .types import (
    ActionTier,
    AgentAction,
    GuardConfig,
    GuardContext,
    GuardDecision,
    GuardEvent,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  event_type TEXT NOT NULL,
  action_tier TEXT,
  decision TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  source TEXT,
  channel TEXT,
  origin_trust TEXT,
  data_sensitivity TEXT,
  input_hash TEXT,
  action_hash TEXT,
  chain_id TEXT,
  message TEXT
);
"""

_COLUMNS = [
    "ts", "event_type", "action_tier", "decision", "reason_code", "source",
    "channel", "origin_trust", "data_sensitivity", "input_hash", "action_hash",
    "chain_id", "message",
]


class AuditLog:
    """Append-only audit sink. Backend: ``sqlite`` (default), ``jsonl``, ``both``."""

    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        backend: Optional[str] = None,
        path: Optional[str] = None,
        jsonl_path: Optional[str] = None,
    ):
        audit_cfg = dict(config.audit) if config else {}
        self.backend = (backend or audit_cfg.get("backend") or "sqlite").lower()
        self.path = path or audit_cfg.get("path") or "guard-audit.db"
        self.jsonl_path = jsonl_path or audit_cfg.get("jsonl_path") or "guard-audit.jsonl"
        self._conn: Optional[sqlite3.Connection] = None
        if self.backend in ("sqlite", "both"):
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        self._conn = sqlite3.connect(self.path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record(self, event: GuardEvent) -> None:
        if self.backend in ("sqlite", "both"):
            self._record_sqlite(event)
        if self.backend in ("jsonl", "both"):
            self._record_jsonl(event)

    def _record_sqlite(self, event: GuardEvent) -> None:
        if self._conn is None:
            self._init_sqlite()
        assert self._conn is not None
        data = event.to_dict()
        placeholders = ", ".join("?" for _ in _COLUMNS)
        self._conn.execute(
            f"INSERT INTO events ({', '.join(_COLUMNS)}) VALUES ({placeholders})",
            [data.get(col) for col in _COLUMNS],
        )
        self._conn.commit()

    def _record_jsonl(self, event: GuardEvent) -> None:
        with open(self.jsonl_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def last(self, n: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent ``n`` events, newest first."""
        if self.backend in ("sqlite", "both"):
            return self._last_sqlite(n)
        return self._last_jsonl(n)

    def _last_sqlite(self, n: int) -> List[Dict[str, Any]]:
        if self._conn is None:
            self._init_sqlite()
        assert self._conn is not None
        cursor = self._conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM events ORDER BY id DESC LIMIT ?",
            (n,),
        )
        return [dict(zip(_COLUMNS, row)) for row in cursor.fetchall()]

    def _last_jsonl(self, n: int) -> List[Dict[str, Any]]:
        if not os.path.exists(self.jsonl_path):
            return []
        with open(self.jsonl_path, "r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        records = [json.loads(line) for line in lines[-n:]]
        records.reverse()
        return records

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


def record_event(event: GuardEvent, config: Optional[GuardConfig] = None) -> None:
    """Record a single event using the configured default backend."""
    log = AuditLog(config=config)
    try:
        log.record(event)
    finally:
        log.close()


def build_event(
    event_type: str,
    decision: GuardDecision,
    *,
    action: Optional[AgentAction] = None,
    tier: Optional[ActionTier] = None,
    context: Optional[GuardContext] = None,
    source: Optional[str] = None,
    channel: Optional[str] = None,
    input_hash: Optional[str] = None,
    chain_id: Optional[str] = None,
) -> GuardEvent:
    """Assemble a ``GuardEvent`` from a decision plus action/context."""
    return GuardEvent(
        ts=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        decision=decision.decision.value,
        reason_code=decision.reason_code.value,
        action_tier=tier.value if tier else None,
        source=source or (context.current_channel if context else None),
        channel=channel or (context.current_channel if context else None),
        origin_trust=context.origin_trust.value if context else None,
        data_sensitivity=context.data_sensitivity.value if context else None,
        input_hash=input_hash,
        action_hash=_action_hash(action) if action else None,
        chain_id=chain_id or (context.chain_id if context else None),
        message=decision.message,
    )


def _action_hash(action: AgentAction) -> str:
    raw = "|".join(
        str(part) for part in (action.kind, action.method, action.target, action.payload)
    )
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

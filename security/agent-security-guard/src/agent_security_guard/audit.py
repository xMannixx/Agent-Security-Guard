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
import threading
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


_BACKENDS = ("sqlite", "jsonl", "both", "none")


class AuditLog:
    """Append-only audit sink. Backend: ``sqlite`` (default), ``jsonl``,
    ``both``, or ``none`` for no audit on purpose."""

    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        backend: Optional[str] = None,
        path: Optional[str] = None,
        jsonl_path: Optional[str] = None,
    ):
        audit_cfg = dict(config.audit) if config else {}
        self.backend = str(backend or audit_cfg.get("backend") or "sqlite").strip().lower()
        if self.backend not in _BACKENDS:
            # Any other name used to match neither branch below: no file was
            # opened, nothing was recorded, and nothing said so.
            raise ValueError(
                f"audit backend '{self.backend}' is not one of {', '.join(_BACKENDS)}"
            )
        self.path = path or audit_cfg.get("path") or "guard-audit.db"
        self.jsonl_path = jsonl_path or audit_cfg.get("jsonl_path") or "guard-audit.jsonl"
        self._conn: Optional[sqlite3.Connection] = None
        # Hosts evaluate tool calls from worker threads. The lock serializes
        # every use of the connection, so it need not stay on the thread that
        # opened it (sqlite3 otherwise raises on the first call from another).
        self._lock = threading.Lock()
        if self.backend in ("sqlite", "both"):
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record(self, event: GuardEvent) -> None:
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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
        action_hash=action_hash(action) if action else None,
        chain_id=chain_id or (context.chain_id if context else None),
        message=decision.message,
    )


def action_hash(action: AgentAction) -> str:
    """SHA-256 over every field of an action, each kept apart from the next.

    A confirmation is bound to this hash, so two different actions must not
    share one. The fields used to be joined with ``|``: target ``a|b`` with
    payload ``c`` hashed like target ``a`` with payload ``b|c``, and ``None``
    like the text ``None``. Lane, source and metadata were not hashed at all.
    """
    fields = [
        action.kind, action.method, action.target, action.payload,
        action.desired_memory_lane, action.memory_source, action.metadata,
    ]
    try:
        raw = json.dumps(
            fields, sort_keys=True, ensure_ascii=False, default=repr,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):  # keys that do not sort, or a cycle
        raw = "".join(f"{len(text)}:{text}" for text in map(repr, fields))
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

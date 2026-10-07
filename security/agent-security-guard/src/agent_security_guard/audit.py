"""Audit logging: ``record_event`` over a SQLite (default) or JSONL backend.

The schema is fixed up front so chains stay reconstructable. ``chain_id`` links
events that belong to the same task/sequence; ``audit --last N`` reads them back
newest-first.

Three things about the trail itself:

- **Where it lives.** Not in the working directory. That is the agent's
  workspace: a cloned repository could ship a ``guard-audit.db`` that is no
  database (and so switch audit off) or a ``guard-audit.jsonl`` that is a link
  to some other file (and have the guard append to it). A path from the
  configuration that is not absolute is taken relative to the guard's state
  directory, ``$XDG_STATE_HOME/agent-security-guard`` or
  ``~/.local/state/agent-security-guard``.
- **Who may read it.** The file is created with mode ``0600`` and its
  directory with ``0700``; an existing file is tightened to that. A link in
  the file's place is not followed.
- **Whether it was changed.** Every record carries the hash of the record
  before it and a hash of itself. ``verify`` walks that chain: a record that
  was edited, removed from the middle or the start, or put in afterwards
  breaks it. It cannot show that the newest records were cut off, or that the
  whole chain was computed anew by someone who can write the file: for that,
  compare ``head`` with a copy kept elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # advisory locking for the JSONL chain; absent on Windows
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

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
  message TEXT,
  prev_hash TEXT,
  hash TEXT
);
"""

_COLUMNS = [
    "ts", "event_type", "action_tier", "decision", "reason_code", "source",
    "channel", "origin_trust", "data_sensitivity", "input_hash", "action_hash",
    "chain_id", "message",
]
# The two columns that link a record to the one before it.
_CHAIN_COLUMNS = ["prev_hash", "hash"]

_BACKENDS = ("sqlite", "jsonl", "both", "none")
_NO_FOLLOW = getattr(os, "O_NOFOLLOW", 0)
_TAIL_BYTES = 65536


def default_audit_dir() -> str:
    """The guard's state directory, where the trail lives unless the
    configuration names an absolute path."""
    base = os.environ.get("XDG_STATE_HOME", "").strip()
    if not os.path.isabs(base):  # unset, or relative, which XDG says to ignore
        base = os.path.join(str(Path.home()), ".local", "state")
    return os.path.join(base, "agent-security-guard")


@dataclass
class ChainCheck:
    """What ``AuditLog.verify`` found."""

    ok: bool
    records: int        # records the chain covers
    unchained: int      # older records, written before records were chained
    head: str           # hash of the newest record, "" if there is none
    problem: str = ""   # what is wrong and at which record

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok, "records": self.records, "unchained": self.unchained,
            "head": self.head, "problem": self.problem,
        }


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
        # A path handed to the constructor is the caller's and taken as it is.
        # One from the configuration is kept out of the working directory.
        self.path = path or _in_audit_dir(audit_cfg.get("path") or "guard-audit.db")
        self.jsonl_path = jsonl_path or _in_audit_dir(
            audit_cfg.get("jsonl_path") or "guard-audit.jsonl"
        )
        self._conn: Optional[sqlite3.Connection] = None
        # Hosts evaluate tool calls from worker threads. The lock serializes
        # every use of the connection, so it need not stay on the thread that
        # opened it (sqlite3 otherwise raises on the first call from another).
        self._lock = threading.Lock()
        if self.backend in ("sqlite", "both"):
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        if self.path != ":memory:":
            _make_private(self.path)
        # Transactions are opened by hand in _record_sqlite.
        self._conn = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None
        )
        self._conn.executescript(_SCHEMA)
        present = {row[1] for row in self._conn.execute("PRAGMA table_info(events)")}
        for column in _CHAIN_COLUMNS:  # a database from before records were chained
            if column not in present:
                self._conn.execute(f"ALTER TABLE events ADD COLUMN {column} TEXT")

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
        columns = _COLUMNS + _CHAIN_COLUMNS
        placeholders = ", ".join("?" for _ in columns)
        # IMMEDIATE takes the write lock before the newest hash is read, so
        # two processes writing to one database cannot both chain to it.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT hash FROM events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = (row[0] if row else None) or ""
            self._conn.execute(
                f"INSERT INTO events ({', '.join(columns)}) VALUES ({placeholders})",
                [data.get(col) for col in _COLUMNS] + [previous, _chain_hash(previous, data)],
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def _record_jsonl(self, event: GuardEvent) -> None:
        data = {col: event.to_dict().get(col) for col in _COLUMNS}
        descriptor = _make_private(self.jsonl_path, keep_open=True)
        with os.fdopen(descriptor, "r+b") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            previous = _newest_jsonl_hash(handle)
            data["prev_hash"] = previous
            data["hash"] = _chain_hash(previous, data)
            handle.seek(0, os.SEEK_END)
            handle.write((json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8"))

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
        records = [
            {col: record.get(col) for col in _COLUMNS}
            for record in self._read_jsonl()[-n:]
        ]
        records.reverse()
        return records

    def _read_jsonl(self) -> List[Dict[str, Any]]:
        if self.backend == "none" or not os.path.exists(self.jsonl_path):
            return []
        with open(self.jsonl_path, "r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def verify(self) -> ChainCheck:
        """Walk the hash chain of the trail and say whether it holds.

        With ``both`` backends each file has a chain of its own and both are
        walked; the counts and the head are those of the database.
        """
        with self._lock:
            checks = []
            if self.backend in ("sqlite", "both"):
                if self._conn is None:
                    self._init_sqlite()
                assert self._conn is not None
                rows = self._conn.execute(
                    f"SELECT id, {', '.join(_COLUMNS + _CHAIN_COLUMNS)} "
                    "FROM events ORDER BY id"
                ).fetchall()
                names = _COLUMNS + _CHAIN_COLUMNS
                checks.append(_walk_chain(
                    (f"record {row[0]}", dict(zip(names, row[1:]))) for row in rows
                ))
            if self.backend in ("jsonl", "both"):
                try:
                    records = self._read_jsonl()
                except ValueError as exc:
                    checks.append(ChainCheck(False, 0, 0, "", f"unreadable line: {exc}"))
                else:
                    checks.append(_walk_chain(
                        (f"line {number}", record)
                        for number, record in enumerate(records, start=1)
                    ))
            if not checks:
                return ChainCheck(True, 0, 0, "")
            first = checks[0]
            problem = "; ".join(check.problem for check in checks if check.problem)
            return ChainCheck(
                all(check.ok for check in checks), first.records, first.unchained,
                first.head, problem,
            )

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


def _in_audit_dir(path: str) -> str:
    expanded = os.path.expanduser(str(path))
    if os.path.isabs(expanded) or expanded == ":memory:":
        return expanded
    return os.path.join(default_audit_dir(), expanded)


def _make_private(path: str, keep_open: bool = False) -> int:
    """Create the file if it is missing, for its owner alone, and return a
    descriptor for it (closed again unless ``keep_open``).

    The directory is made for the owner alone too, where this creates it. A
    symbolic link in the file's place is refused rather than followed, and an
    existing file that others may read or write is tightened.
    """
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | _NO_FOLLOW, 0o600)
    try:
        if os.fstat(descriptor).st_mode & 0o077 and hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
    except OSError:  # not ours to change; it stays readable as it was
        pass
    if keep_open:
        return descriptor
    os.close(descriptor)
    return -1


def _chain_hash(previous: str, data: Dict[str, Any]) -> str:
    """Hash of a record together with the hash of the record before it."""
    body = json.dumps(
        {col: data.get(col) for col in _COLUMNS},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(f"{previous}\n{body}".encode("utf-8", errors="replace")).hexdigest()


def _newest_jsonl_hash(handle) -> str:
    """Hash of the last record in an open JSONL file, "" if it has none."""
    size = handle.seek(0, os.SEEK_END)
    handle.seek(max(0, size - _TAIL_BYTES))
    tail = handle.read()
    lines = [line for line in tail.splitlines() if line.strip()]
    if len(lines) == 1 and size > _TAIL_BYTES:  # one line longer than the tail
        handle.seek(0)
        lines = [line for line in handle.read().splitlines() if line.strip()]
    if not lines:
        return ""
    try:
        return str(json.loads(lines[-1].decode("utf-8")).get("hash") or "")
    except (ValueError, AttributeError):
        return ""


def _walk_chain(records) -> ChainCheck:
    """Check ``(label, record)`` pairs, oldest first, against their hashes."""
    covered = 0
    unchained = 0
    previous = ""
    for label, record in records:
        if not record.get("hash"):
            if covered:
                return ChainCheck(
                    False, covered, unchained, previous,
                    f"{label} carries no hash but follows records that do",
                )
            unchained += 1
            continue
        if (record.get("prev_hash") or "") != previous:
            return ChainCheck(
                False, covered, unchained, previous,
                f"{label} does not follow the record before it "
                "(a record was removed, added or reordered)",
            )
        if record["hash"] != _chain_hash(previous, record):
            return ChainCheck(
                False, covered, unchained, previous, f"{label} was changed after it was written"
            )
        previous = record["hash"]
        covered += 1
    return ChainCheck(True, covered, unchained, previous)


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

import json
import os
import sqlite3
import threading
from pathlib import Path

import pytest

from agent_security_guard import (
    ActionTier,
    AgentAction,
    AuditLog,
    Decision,
    GuardContext,
    OriginTrust,
    build_event,
    check_action,
    load_config,
)
from agent_security_guard.audit import default_audit_dir

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes and links")


def _decision():
    return check_action(AgentAction(kind="shell", target="x"),
                        GuardContext(origin_trust=OriginTrust.EXTERNAL_WEB))


def test_build_event_from_decision():
    action = AgentAction(kind="shell", target="rm -rf /")
    ctx = GuardContext(origin_trust=OriginTrust.EXTERNAL_WEB, chain_id="c1")
    event = build_event("tool_call", _decision(), action=action,
                        tier=ActionTier.EXECUTION, context=ctx)
    assert event.decision == "deny"
    assert event.reason_code == "UNTRUSTED_TO_SHELL"
    assert event.action_tier == "execution"
    assert event.origin_trust == "external_web"
    assert event.chain_id == "c1"
    assert len(event.action_hash) == 64


def test_audit_hash_tells_two_actions_apart():
    one = build_event("tool_call", _decision(), action=AgentAction(kind="shell", target="a|b", payload="c"))
    other = build_event("tool_call", _decision(), action=AgentAction(kind="shell", target="a", payload="b|c"))
    assert one.action_hash != other.action_hash


def test_sqlite_roundtrip(tmp_path):
    db = tmp_path / "audit.db"
    log = AuditLog(backend="sqlite", path=str(db))
    for i in range(3):
        log.record(build_event(f"e{i}", _decision()))
    rows = log.last(10)
    log.close()
    assert len(rows) == 3
    # Newest first.
    assert rows[0]["event_type"] == "e2"
    assert rows[0]["decision"] == "deny"


def test_jsonl_roundtrip(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(backend="jsonl", jsonl_path=str(path))
    log.record(build_event("first", _decision()))
    log.record(build_event("second", _decision()))
    rows = log.last(10)
    assert [r["event_type"] for r in rows] == ["second", "first"]
    # File is valid JSONL.
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["reason_code"] == "UNTRUSTED_TO_SHELL"


def test_both_backends(tmp_path):
    log = AuditLog(backend="both", path=str(tmp_path / "a.db"),
                   jsonl_path=str(tmp_path / "a.jsonl"))
    log.record(build_event("x", _decision()))
    assert len(log.last(5)) == 1
    log.close()
    assert (tmp_path / "a.jsonl").exists()


def test_last_limit(tmp_path):
    log = AuditLog(backend="sqlite", path=str(tmp_path / "a.db"))
    for i in range(10):
        log.record(build_event(f"e{i}", _decision()))
    assert len(log.last(4)) == 4
    log.close()


def test_unknown_backend_raises_instead_of_recording_nothing(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="sqllite"):
        AuditLog(backend="sqllite", path=str(tmp_path / "audit.db"))


def test_backend_none_is_no_audit_on_purpose(tmp_path):
    log = AuditLog(backend="none", path=str(tmp_path / "audit.db"),
                   jsonl_path=str(tmp_path / "audit.jsonl"))
    log.record(build_event("e", _decision()))
    assert log.last(5) == []
    assert not (tmp_path / "audit.db").exists()
    assert not (tmp_path / "audit.jsonl").exists()
    log.close()


# --------------------------------------------------------------------------- #
# Where the trail lives
# --------------------------------------------------------------------------- #


@pytest.fixture
def state_home(tmp_path, monkeypatch):
    """A state directory and a separate working directory, both empty."""
    home = tmp_path / "state-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("XDG_STATE_HOME", str(home))
    monkeypatch.chdir(workspace)
    return home


def test_default_trail_is_in_the_state_directory_not_the_working_directory(state_home):
    log = AuditLog()
    log.record(build_event("e", _decision()))
    log.close()
    assert log.path == str(state_home / "agent-security-guard" / "guard-audit.db")
    assert os.path.exists(log.path)
    assert os.listdir(".") == []


@pytest.mark.parametrize("backend,key", [("sqlite", "path"), ("jsonl", "jsonl_path")])
def test_relative_path_from_the_configuration_goes_to_the_state_directory(state_home, backend, key):
    config = load_config(None)
    config.audit = {"backend": backend, key: "trail/events.log"}
    log = AuditLog(config=config)
    log.record(build_event("e", _decision()))
    log.close()
    assert (state_home / "agent-security-guard" / "trail" / "events.log").exists()
    assert os.listdir(".") == []


def test_absolute_path_from_the_configuration_is_used_as_it_is(state_home, tmp_path):
    config = load_config(None)
    config.audit = {"backend": "sqlite", "path": str(tmp_path / "elsewhere" / "a.db")}
    log = AuditLog(config=config)
    log.close()
    assert (tmp_path / "elsewhere" / "a.db").exists()
    assert not state_home.exists()


def test_path_given_to_the_constructor_is_the_callers(state_home):
    log = AuditLog(path="mine.db")
    log.close()
    assert os.path.exists("mine.db")


def test_state_directory_without_xdg_is_under_home(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert default_audit_dir() == str(tmp_path / ".local" / "state" / "agent-security-guard")
    # XDG says a relative value is to be ignored; it would mean the working directory.
    monkeypatch.setenv("XDG_STATE_HOME", "state")
    assert default_audit_dir() == str(tmp_path / ".local" / "state" / "agent-security-guard")


# --------------------------------------------------------------------------- #
# Who may read it
# --------------------------------------------------------------------------- #


def _mode(path):
    return os.stat(path).st_mode & 0o777


@posix_only
@pytest.mark.parametrize("backend", ["sqlite", "jsonl", "both"])
def test_trail_is_created_for_its_owner_alone(state_home, backend):
    previous = os.umask(0o022)  # the usual umask, under which it was 0644
    try:
        log = AuditLog(backend=backend)
        log.record(build_event("e", _decision()))
        log.close()
    finally:
        os.umask(previous)
    directory = state_home / "agent-security-guard"
    assert _mode(directory) == 0o700
    files = sorted(os.listdir(directory))
    assert files
    for name in files:
        assert _mode(directory / name) == 0o600, name


@posix_only
@pytest.mark.parametrize("backend,name", [("sqlite", "a.db"), ("jsonl", "a.jsonl")])
def test_existing_trail_that_others_can_read_is_tightened(tmp_path, backend, name):
    path = tmp_path / name
    path.touch()
    os.chmod(path, 0o644)
    log = AuditLog(backend=backend, path=str(path), jsonl_path=str(path))
    log.record(build_event("e", _decision()))
    log.close()
    assert _mode(path) == 0o600


@posix_only
def test_link_in_place_of_the_database_is_not_followed(tmp_path):
    victim = tmp_path / "victim.db"
    link = tmp_path / "guard-audit.db"
    os.symlink(victim, link)
    with pytest.raises(OSError):
        AuditLog(backend="sqlite", path=str(link))
    assert not victim.exists()


@posix_only
def test_link_in_place_of_the_jsonl_file_is_not_appended_through(tmp_path):
    victim = tmp_path / "authorized_keys"
    victim.write_text("ssh-ed25519 AAAA user\n", encoding="utf-8")
    link = tmp_path / "guard-audit.jsonl"
    os.symlink(victim, link)
    log = AuditLog(backend="jsonl", jsonl_path=str(link))
    with pytest.raises(OSError):
        log.record(build_event("e", _decision()))
    assert victim.read_text(encoding="utf-8") == "ssh-ed25519 AAAA user\n"


# --------------------------------------------------------------------------- #
# Whether it was changed
# --------------------------------------------------------------------------- #


def _filled(tmp_path, backend="sqlite", count=5):
    log = AuditLog(backend=backend, path=str(tmp_path / "a.db"),
                   jsonl_path=str(tmp_path / "a.jsonl"))
    for i in range(count):
        log.record(build_event(f"e{i}", _decision()))
    return log


def _sql(tmp_path, statement):
    connection = sqlite3.connect(str(tmp_path / "a.db"))
    connection.execute(statement)
    connection.commit()
    connection.close()


@pytest.mark.parametrize("backend", ["sqlite", "jsonl", "both"])
def test_untouched_trail_verifies(tmp_path, backend):
    log = _filled(tmp_path, backend)
    check = log.verify()
    log.close()
    assert check.ok is True
    assert check.records == 5
    assert check.unchained == 0
    assert len(check.head) == 64
    assert check.problem == ""


def test_empty_trail_verifies(tmp_path):
    log = _filled(tmp_path, count=0)
    assert log.verify().to_dict() == {
        "ok": True, "records": 0, "unchained": 0, "head": "", "problem": "",
    }
    log.close()


@pytest.mark.parametrize("statement,says", [
    ("UPDATE events SET decision = 'allow' WHERE id = 3", "changed"),
    ("UPDATE events SET message = 'nothing to see' WHERE id = 5", "changed"),
    ("UPDATE events SET ts = '2020-01-01T00:00:00+00:00' WHERE id = 1", "changed"),
    ("DELETE FROM events WHERE id = 3", "removed"),
    ("DELETE FROM events WHERE id = 1", "removed"),
    ("DELETE FROM events WHERE id < 4", "removed"),
    ("UPDATE events SET hash = NULL, prev_hash = NULL WHERE id = 4", "no hash"),
    ("INSERT INTO events (ts, event_type, decision, reason_code) "
     "VALUES ('2026-01-01', 'tool_call', 'allow', 'ALLOW_DEFAULT')", "no hash"),
])
def test_changed_database_does_not_verify(tmp_path, statement, says):
    _filled(tmp_path).close()
    _sql(tmp_path, statement)
    log = AuditLog(backend="sqlite", path=str(tmp_path / "a.db"))
    check = log.verify()
    log.close()
    assert check.ok is False
    assert says in check.problem


def _rewrite_lines(tmp_path, change):
    path = tmp_path / "a.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(change(lines)) + "\n", encoding="utf-8")


@pytest.mark.parametrize("change", [
    lambda lines: lines[:2] + [lines[2].replace('"deny"', '"allow"')] + lines[3:],
    lambda lines: lines[:2] + lines[3:],                 # one removed
    lambda lines: lines[1:],                             # the first removed
    lambda lines: [lines[1], lines[0]] + lines[2:],      # reordered
    lambda lines: lines + ['{"ts": "x", "event_type": "forged", "decision": "allow"}'],
    lambda lines: lines[:2] + ["not json"] + lines[2:],
])
def test_changed_jsonl_file_does_not_verify(tmp_path, change):
    _filled(tmp_path, "jsonl").close()
    _rewrite_lines(tmp_path, change)
    log = AuditLog(backend="jsonl", jsonl_path=str(tmp_path / "a.jsonl"))
    assert log.verify().ok is False


def test_what_the_chain_cannot_show_is_a_cut_off_end(tmp_path):
    # Known limit, stated in the module: the newest records can be removed
    # without breaking the chain. The head is what gives it away, if a copy of
    # it was kept elsewhere.
    log = _filled(tmp_path)
    head_before = log.verify().head
    log.close()
    _sql(tmp_path, "DELETE FROM events WHERE id > 3")
    log = AuditLog(backend="sqlite", path=str(tmp_path / "a.db"))
    check = log.verify()
    log.close()
    assert check.ok is True
    assert check.records == 3
    assert check.head != head_before


def test_head_moves_with_every_record(tmp_path):
    log = _filled(tmp_path, count=1)
    first = log.verify().head
    log.record(build_event("next", _decision()))
    assert log.verify().head != first
    log.close()


def test_two_writers_on_one_database_keep_one_chain(tmp_path):
    one = _filled(tmp_path, count=0)
    other = AuditLog(backend="sqlite", path=str(tmp_path / "a.db"))
    for i in range(10):
        (one if i % 2 else other).record(build_event(f"e{i}", _decision()))
    check = one.verify()
    one.close()
    other.close()
    assert check.ok is True
    assert check.records == 10


def test_two_writers_on_one_jsonl_file_keep_one_chain(tmp_path):
    one = _filled(tmp_path, "jsonl", count=0)
    other = AuditLog(backend="jsonl", jsonl_path=str(tmp_path / "a.jsonl"))
    for i in range(10):
        (one if i % 2 else other).record(build_event(f"e{i}", _decision()))
    assert one.verify().ok is True
    assert one.verify().records == 10


@pytest.mark.parametrize("backend", ["sqlite", "jsonl"])
def test_records_from_many_threads_keep_one_chain(tmp_path, backend):
    log = _filled(tmp_path, backend, count=0)
    workers = [
        threading.Thread(
            target=lambda: [log.record(build_event("e", _decision())) for _ in range(20)]
        )
        for _ in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    check = log.verify()
    log.close()
    assert check.ok is True
    assert check.records == 80


def test_database_from_before_chaining_keeps_working(tmp_path):
    # The table as 0.3.0 created it, with two records in it.
    connection = sqlite3.connect(str(tmp_path / "a.db"))
    connection.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "event_type TEXT NOT NULL, action_tier TEXT, decision TEXT NOT NULL, "
        "reason_code TEXT NOT NULL, source TEXT, channel TEXT, origin_trust TEXT, "
        "data_sensitivity TEXT, input_hash TEXT, action_hash TEXT, chain_id TEXT, message TEXT)"
    )
    for i in range(2):
        connection.execute(
            "INSERT INTO events (ts, event_type, decision, reason_code) VALUES (?, ?, ?, ?)",
            (f"2026-01-0{i + 1}", "old", "deny", "UNTRUSTED_TO_SHELL"),
        )
    connection.commit()
    connection.close()

    log = AuditLog(backend="sqlite", path=str(tmp_path / "a.db"))
    log.record(build_event("new", _decision()))
    log.record(build_event("newer", _decision()))
    assert [row["event_type"] for row in log.last(10)] == ["newer", "new", "old", "old"]
    check = log.verify()
    log.close()
    assert check.ok is True
    assert check.records == 2
    assert check.unchained == 2


def test_jsonl_file_from_before_chaining_keeps_working(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_text('{"ts": "2026-01-01", "event_type": "old", "decision": "deny"}\n', encoding="utf-8")
    log = AuditLog(backend="jsonl", jsonl_path=str(path))
    log.record(build_event("new", _decision()))
    assert [row["event_type"] for row in log.last(10)] == ["new", "old"]
    check = log.verify()
    assert (check.ok, check.records, check.unchained) == (True, 1, 1)

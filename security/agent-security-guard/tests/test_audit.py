import json

from agent_security_guard import (
    ActionTier,
    AgentAction,
    AuditLog,
    Decision,
    GuardContext,
    OriginTrust,
    build_event,
    check_action,
)


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

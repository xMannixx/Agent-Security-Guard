from agent_security_guard import (
    AgentAction,
    Decision,
    GuardContext,
    OriginTrust,
    ReasonCode,
    UserIntentOrigin,
    check_action,
)


def test_check_action_end_to_end_read():
    d = check_action(AgentAction(kind="http_get", target="https://x"),
                     GuardContext(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.ALLOW
    assert d.risk_score == 0.0


def test_check_action_classifies_then_decides_shell():
    d = check_action(AgentAction(kind="shell", target="rm -rf /"),
                     GuardContext(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_SHELL
    assert d.risk_score >= 0.9


def test_risk_score_tracks_decision_severity():
    confirm = check_action(
        AgentAction(kind="http_post"),
        GuardContext(origin_trust=OriginTrust.TRUSTED_USER,
                     user_intent_origin=UserIntentOrigin.HUMAN_EXPLICIT),
    )
    assert confirm.decision is Decision.REQUIRE_CONFIRMATION
    assert 0.5 <= confirm.risk_score < 0.9


def test_decision_to_dict_is_serializable():
    d = check_action(AgentAction(kind="shell"),
                     GuardContext(origin_trust=OriginTrust.EXTERNAL_WEB))
    payload = d.to_dict()
    assert payload["decision"] == "deny"
    assert payload["reason_code"] == "UNTRUSTED_TO_SHELL"

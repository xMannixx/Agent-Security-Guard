from agent_security_guard import (
    Decision,
    GuardContext,
    OriginTrust,
    ReasonCode,
    UserIntentOrigin,
    advise_memory_write,
)


def test_external_to_authorization_denied_suggests_evidence():
    a = advise_memory_write("perm granted", "authorization", "external")
    assert a.decision is Decision.DENY
    assert a.reason_code is ReasonCode.UNTRUSTED_TO_AUTH_MEMORY
    assert a.suggested_lane == "evidence"


def test_external_to_procedural_denied():
    a = advise_memory_write("always do x", "procedural", "tool")
    assert a.decision is Decision.DENY
    assert a.reason_code is ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY


def test_observation_to_authorization_allowed():
    a = advise_memory_write("user is admin", "authorization", "observation")
    assert a.decision is Decision.ALLOW
    assert a.suggested_lane == "authorization"


def test_external_to_evidence_allowed_with_warning():
    a = advise_memory_write("server runs ubuntu", "evidence", "external")
    assert a.decision is Decision.ALLOW_WITH_WARNING
    assert a.reason_code is ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY
    assert a.suggested_lane == "evidence"


def test_external_to_identity_requires_confirmation():
    a = advise_memory_write("name is X", "identity", "external")
    assert a.decision is Decision.REQUIRE_CONFIRMATION
    assert a.reason_code is ReasonCode.UNTRUSTED_TO_IDENTITY_MEMORY


def test_conversation_to_identity_allowed():
    a = advise_memory_write("name is X", "identity", "conversation")
    assert a.decision is Decision.ALLOW


def test_untrusted_origin_via_context_blocks_authorization():
    ctx = GuardContext(origin_trust=OriginTrust.EXTERNAL_WEB)
    a = advise_memory_write("perm", "authorization", "observation", ctx)
    assert a.decision is Decision.DENY


def test_untrusted_suggestion_via_context():
    ctx = GuardContext(user_intent_origin=UserIntentOrigin.UNTRUSTED_SUGGESTION)
    a = advise_memory_write("perm", "authorization", "observation", ctx)
    assert a.decision is Decision.DENY


def test_secret_content_note():
    a = advise_memory_write("api_key = abc123", "evidence", "observation")
    assert "secret material" in a.message

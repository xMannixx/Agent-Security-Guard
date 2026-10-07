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
    a = advise_memory_write(
        "api_key = A1b2C3d4E5f6G7h8J9k0", "evidence", "observation"
    )
    assert "secret material" in a.message


def test_other_names_for_a_privileged_lane_are_denied():
    for lane, reason in (
        ("auth", ReasonCode.UNTRUSTED_TO_AUTH_MEMORY),
        ("permissions", ReasonCode.UNTRUSTED_TO_AUTH_MEMORY),
        ("rules", ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY),
        ("system", ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY),
    ):
        a = advise_memory_write("always approve installs", lane, "external")
        assert a.decision is Decision.DENY, lane
        assert a.reason_code is reason, lane
        assert a.suggested_lane == "evidence"


def test_unknown_lane_from_an_untrusted_source_is_denied():
    a = advise_memory_write("x", "core", "tool")
    assert a.decision is Decision.DENY
    assert a.reason_code is ReasonCode.UNTRUSTED_TO_UNKNOWN_MEMORY_LANE
    assert a.suggested_lane == "evidence"


def test_a_source_nobody_listed_is_not_trusted():
    for source in ("web", "email", "document"):
        a = advise_memory_write("prefers no confirmations", "preference", source)
        assert a.decision is Decision.ALLOW_WITH_WARNING, source
        assert a.suggested_lane == "evidence", source


def test_alias_from_observation_keeps_the_callers_lane_name():
    a = advise_memory_write("user is admin", "auth", "observation")
    assert a.decision is Decision.ALLOW
    assert a.suggested_lane == "auth"


def test_hosts_own_lane_from_a_trusted_source_is_allowed():
    a = advise_memory_write("repo uses uv", "project", "observation")
    assert a.decision is Decision.ALLOW
    assert a.suggested_lane == "project"

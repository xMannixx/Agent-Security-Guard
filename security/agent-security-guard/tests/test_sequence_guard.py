from agent_security_guard import (
    ActionHistory,
    ActionTier,
    AgentAction,
    DataSensitivity,
    Decision,
    GuardContext,
    HistoryEntry,
    OriginTrust,
    ReasonCode,
    SequenceCategory,
    UserIntentOrigin,
    check_sequence,
    derive_category,
)


def hist(*entries) -> ActionHistory:
    h = ActionHistory()
    for e in entries:
        h.record(e)
    return h


def secret_read_entry():
    return HistoryEntry(tier=ActionTier.LOCAL_READ,
                        origin_trust=OriginTrust.LOCAL_PROJECT,
                        data_sensitivity=DataSensitivity.SECRET,
                        target=".env")


def web_read_entry():
    return HistoryEntry(tier=ActionTier.READ_ONLY,
                        origin_trust=OriginTrust.EXTERNAL_WEB,
                        target="https://x")


def download_entry(untrusted=True):
    return HistoryEntry(tier=ActionTier.DOWNLOAD,
                        origin_trust=OriginTrust.EXTERNAL_WEB if untrusted else OriginTrust.TRUSTED_USER,
                        target="https://x/a.sh")


# --------------------------------------------------------------------------- #
# derive_category
# --------------------------------------------------------------------------- #


def test_secret_read_category():
    cat = derive_category(ActionTier.LOCAL_READ, OriginTrust.LOCAL_PROJECT, DataSensitivity.SECRET)
    assert cat is SequenceCategory.SECRET_READ


def test_untrusted_read_is_web_read():
    assert derive_category(ActionTier.READ_ONLY, OriginTrust.EXTERNAL_WEB) is SequenceCategory.WEB_READ
    assert derive_category(ActionTier.READ_ONLY, OriginTrust.TRUSTED_USER) is SequenceCategory.READ_ONLY


# --------------------------------------------------------------------------- #
# Kill chains
# --------------------------------------------------------------------------- #


def test_secret_read_then_external_post_denied():
    history = hist(secret_read_entry())
    action = AgentAction(kind="http_post", target="https://exfil")
    d = check_sequence(action, history, GuardContext(origin_trust=OriginTrust.TRUSTED_USER))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.SECRET_THEN_EXFIL


def test_secret_read_then_summarize_then_post_still_denied():
    history = hist(
        secret_read_entry(),
        HistoryEntry(tier=ActionTier.READ_ONLY, origin_trust=OriginTrust.TRUSTED_USER),  # summarize
    )
    action = AgentAction(kind="http_post", target="https://exfil")
    d = check_sequence(action, history, GuardContext(origin_trust=OriginTrust.TRUSTED_USER))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.SECRET_THEN_EXFIL


def test_untrusted_download_then_execute_denied():
    history = hist(download_entry(untrusted=True))
    action = AgentAction(kind="shell", target="./a.sh")
    d = check_sequence(action, history, GuardContext(origin_trust=OriginTrust.TRUSTED_USER))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.DOWNLOAD_THEN_EXECUTE


def test_user_download_then_execute_requires_confirmation():
    history = hist(download_entry(untrusted=False))
    action = AgentAction(kind="shell", target="./a.sh")
    d = check_sequence(action, history, GuardContext(origin_trust=OriginTrust.TRUSTED_USER))
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.DOWNLOAD_THEN_EXECUTE


def test_web_read_then_shell_denied():
    history = hist(web_read_entry())
    action = AgentAction(kind="shell", target="rm -rf /")
    d = check_sequence(action, history,
                       GuardContext(origin_trust=OriginTrust.TRUSTED_USER,
                                    user_intent_origin=UserIntentOrigin.UNTRUSTED_SUGGESTION))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_SHELL


def test_web_read_then_authorization_memory_denied():
    history = hist(web_read_entry())
    action = AgentAction(kind="memory_write", desired_memory_lane="authorization")
    d = check_sequence(action, history, GuardContext())
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_AUTH_MEMORY


def test_web_read_then_evidence_memory_allowed_with_warning():
    history = hist(web_read_entry())
    action = AgentAction(kind="memory_write", desired_memory_lane="evidence")
    d = check_sequence(action, history, GuardContext())
    assert d.decision is Decision.ALLOW_WITH_WARNING
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY


def test_clean_sequence_allowed():
    history = hist(HistoryEntry(tier=ActionTier.READ_ONLY, origin_trust=OriginTrust.TRUSTED_USER))
    action = AgentAction(kind="http_get", target="https://x")
    d = check_sequence(action, history, GuardContext(origin_trust=OriginTrust.TRUSTED_USER))
    assert d.decision is Decision.ALLOW


def test_chain_id_isolation():
    # A secret read in chain A must not block a post in chain B.
    h = ActionHistory()
    h.record(HistoryEntry(tier=ActionTier.LOCAL_READ, data_sensitivity=DataSensitivity.SECRET,
                          chain_id="A", target=".env"))
    action = AgentAction(kind="http_post", target="https://x")
    ctx_b = GuardContext(origin_trust=OriginTrust.TRUSTED_USER, chain_id="B")
    d = check_sequence(action, h, ctx_b)
    assert d.decision is Decision.ALLOW


def test_record_action_categorizes():
    h = ActionHistory()
    ctx = GuardContext(origin_trust=OriginTrust.EXTERNAL_WEB)
    h.record_action(AgentAction(kind="http_get", target="https://x"), ctx)
    assert len(h) == 1
    assert h.entries[0].tier is ActionTier.READ_ONLY


def test_history_is_bounded():
    h = ActionHistory(max_events=3)
    for _ in range(10):
        h.record(HistoryEntry(tier=ActionTier.READ_ONLY))
    assert len(h) == 3

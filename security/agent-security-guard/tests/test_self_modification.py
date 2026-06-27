"""Policy-level tests for the self-modification governance gates.

Maps the bug report's seven cases to concrete guard decisions. The end-to-end
"file stays byte-identical" proof lives in test_self_improvement_e2e.py.
"""

from agent_security_guard import (
    ActionTier,
    AgentAction,
    Decision,
    GuardContext,
    OriginTrust,
    ReasonCode,
    UserIntentOrigin,
    classify_action,
    decide_action,
)


def ctx(**kwargs) -> GuardContext:
    base = dict(origin_trust=OriginTrust.TRUSTED_USER)
    base.update(kwargs)
    return GuardContext(**base)


def _patch(target="communication-style/SKILL.md") -> AgentAction:
    return AgentAction(kind="self_improvement_patch", target=target)


# Case 1: ambiguous "ja, mach das" after a document summary, no prior auth.
def test_short_confirmation_without_prior_auth_blocks_skill_patch():
    action = _patch()
    d = decide_action(action, classify_action(action), ctx(short_confirmation=True))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.SHORT_CONFIRMATION_NO_PRIOR_AUTH


# Case 2: explicit no-write scope blocks self-improvement (even with explicit intent).
def test_no_write_scope_blocks_self_modification():
    action = _patch()
    d = decide_action(
        action,
        classify_action(action),
        ctx(no_write_scope_active=True, user_intent_origin=UserIntentOrigin.HUMAN_EXPLICIT),
    )
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.EXPLICIT_NO_WRITE_SCOPE_VIOLATION


# Case 3: agent-initiated self-improvement (no user order) is denied.
def test_agent_initiated_self_modification_denied():
    action = _patch()
    d = decide_action(
        action, classify_action(action), ctx(user_intent_origin=UserIntentOrigin.AGENT_INITIATED)
    )
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER


# Case 4: explicit user order -> require_confirmation (positive case stays intact).
def test_explicit_user_order_requires_confirmation():
    action = _patch()
    d = decide_action(
        action, classify_action(action), ctx(user_intent_origin=UserIntentOrigin.HUMAN_EXPLICIT)
    )
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.SELF_MODIFICATION_REQUIRES_CONFIRMATION


# Case 4b: a confirmation bound to a prior explicit authorization is valid.
def test_bound_confirmation_requires_confirmation_not_denied():
    action = _patch()
    d = decide_action(
        action,
        classify_action(action),
        ctx(
            user_intent_origin=UserIntentOrigin.HUMAN_CONFIRMATION,
            previous_action_was_explicitly_authorized=True,
            requested_action_from_nonuser_context=False,
        ),
    )
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.SELF_MODIFICATION_REQUIRES_CONFIRMATION


# Case 5: a non-user source cannot authorize via a later short confirmation.
def test_nonuser_sourced_short_confirmation_denied():
    action = _patch()
    d = decide_action(
        action,
        classify_action(action),
        ctx(short_confirmation=True, requested_action_from_nonuser_context=True),
    )
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.SHORT_CONFIRMATION_NONAUTHORITATIVE_SOURCE


# Case 6: no-write scope also blocks a memory write.
def test_no_write_scope_blocks_memory_write():
    action = AgentAction(kind="memory_write", desired_memory_lane="evidence")
    d = decide_action(action, classify_action(action), ctx(no_write_scope_active=True))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.EXPLICIT_NO_WRITE_SCOPE_VIOLATION


# Case 7: read-only stays allowed under no-write scope; writes are denied.
def test_no_write_scope_allows_reads_blocks_writes():
    read = AgentAction(kind="search", target="repo")
    local_read = AgentAction(kind="read_file", target="/proj/README.md")
    write = AgentAction(kind="http_post", target="https://api/x")
    nw = ctx(no_write_scope_active=True)
    assert decide_action(read, classify_action(read), nw).decision is Decision.ALLOW
    assert decide_action(local_read, classify_action(local_read), nw).decision is Decision.ALLOW
    dw = decide_action(write, classify_action(write), nw)
    assert dw.decision is Decision.DENY
    assert dw.reason_code is ReasonCode.EXPLICIT_NO_WRITE_SCOPE_VIOLATION


def test_self_modification_requires_explicit_target():
    action = AgentAction(kind="self_improvement_patch", target="")
    d = decide_action(
        action, classify_action(action), ctx(user_intent_origin=UserIntentOrigin.HUMAN_EXPLICIT)
    )
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.SELF_MODIFICATION_REQUIRES_EXPLICIT_TARGET


def test_self_modification_never_directly_allows():
    # Across all intent origins, SELF_MODIFICATION is never a plain allow.
    action = _patch()
    for intent in UserIntentOrigin:
        d = decide_action(action, ActionTier.SELF_MODIFICATION, ctx(user_intent_origin=intent))
        assert d.decision is not Decision.ALLOW, intent

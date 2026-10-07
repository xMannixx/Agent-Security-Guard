"""Make the stdlib-only package importable in tests without installation."""

import os
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Repo root, so tests can `import plugin` (the Hermes plugin package).
_REPO_ROOT = Path(__file__).parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _state_dir_of_its_own(tmp_path_factory):
    """Keep the audit trail of a test run out of the real state directory.

    The plugin's adapter is created on the first hook call and keeps its audit
    file for the rest of the run, so this is set once for the whole session.
    """
    previous = os.environ.get("XDG_STATE_HOME")
    os.environ["XDG_STATE_HOME"] = str(tmp_path_factory.mktemp("state"))
    yield
    if previous is None:
        os.environ.pop("XDG_STATE_HOME", None)
    else:
        os.environ["XDG_STATE_HOME"] = previous


@pytest.fixture
def isolated_plugin(monkeypatch, tmp_path):
    """The plugin with fresh state, an empty working directory, and no operator
    policy other than the guard.yaml shipped next to it."""
    import plugin as guard_plugin

    monkeypatch.setattr(guard_plugin, "_adapter", None)
    monkeypatch.setattr(guard_plugin, "_config", None)
    monkeypatch.setattr(guard_plugin, "_config_error", None)
    monkeypatch.setattr(guard_plugin, "_SYSTEM_CONFIG", tmp_path / "etc" / "guard.yaml")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.delenv("AGENT_SECURITY_GUARD_MODE", raising=False)
    monkeypatch.chdir(tmp_path)
    return guard_plugin


@pytest.fixture
def hermes_reads():
    """What Hermes makes of a ``pre_tool_call`` result: ``"block"``,
    ``"approve"``, or ``None`` when it lets the tool run.

    Mirrors its plugin dispatcher: only ``action`` is read, a block needs a
    non-empty message, and a result without a known action is ignored.
    """

    def read(result):
        if not isinstance(result, dict):
            return None
        action = result.get("action")
        if action not in ("block", "approve"):
            return None
        message = result.get("message")
        if action == "block" and not (isinstance(message, str) and message):
            return None
        return action

    return read

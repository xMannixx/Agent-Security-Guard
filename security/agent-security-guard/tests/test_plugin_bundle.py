"""The plugin directory works on its own, as a catalog install gets it.

Hermes installs a catalog entry with ``subdir: plugin`` by checking out only
that directory. Without the package inside it the hooks still register, but
every call is decided by the degraded fallback: that has to be caught here, not
by a user.
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import plugin as guard_plugin

REPO_ROOT = Path(__file__).resolve().parents[3]
PLUGIN_DIR = REPO_ROOT / "plugin"

pytestmark = pytest.mark.skipif(
    not (REPO_ROOT / "scripts" / "bundle_engine.py").is_file(),
    reason="not inside the repository",
)


def _bundle_script():
    spec = importlib.util.spec_from_file_location(
        "bundle_engine", REPO_ROOT / "scripts" / "bundle_engine.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _declared(key):
    """Entries of a top-level ``key:`` list in plugin.yaml."""
    text = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
    block = re.search(rf"^{key}:\n((?:[ \t]+- .*\n?)*)", text, re.MULTILINE)
    assert block, f"plugin.yaml has no {key} list"
    return sorted(line.split("- ", 1)[1].strip() for line in block.group(1).splitlines())


class _Ctx:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, fn):
        self.hooks[name] = fn


def test_the_copy_in_the_plugin_is_the_source_package():
    assert _bundle_script().differences() == []


def test_the_manifest_declares_every_hook_the_plugin_registers():
    ctx = _Ctx()
    guard_plugin.register(ctx)
    assert _declared("provides_hooks") == sorted(ctx.hooks)


def test_the_manifest_states_a_hermes_floor():
    text = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
    assert re.search(r'^requires_hermes: ">=\d+\.\d+(\.\d+)?"$', text, re.MULTILINE)


_PROBE = r"""
import importlib.util, json, sys
from pathlib import Path
plugin_dir = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "guard_plugin", plugin_dir / "__init__.py",
    submodule_search_locations=[str(plugin_dir)])
plugin = importlib.util.module_from_spec(spec)
sys.modules["guard_plugin"] = plugin
spec.loader.exec_module(plugin)
own_file = str(plugin_dir / "__init__.py")
decision = plugin.guard_tool_call(
    tool_name="write_file", args={"path": own_file, "content": "pass"},
    session_id="s", turn_id="t")
status = plugin.guard_status()
print(json.dumps({"status": status, "decision": decision}, default=str))
"""


@pytest.mark.skipif(
    guard_plugin._SYSTEM_PACKAGE.exists(),
    reason="a system-wide package is installed and would be loaded first",
)
def test_the_plugin_directory_alone_runs_its_own_copy(tmp_path):
    installed = tmp_path / "plugins" / "agent-security-guard"
    shutil.copytree(PLUGIN_DIR, installed, ignore=shutil.ignore_patterns("__pycache__"))
    home = tmp_path / "home"
    home.mkdir()
    # A home of its own: HOME on POSIX, USERPROFILE on Windows. The rest of
    # the environment stays (Windows needs e.g. SYSTEMROOT to start Python).
    env = dict(os.environ)
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_STATE_HOME": str(tmp_path / "state"),
    })
    env.pop("AGENT_SECURITY_GUARD_MODE", None)
    result = subprocess.run(
        [sys.executable, "-I", "-c", _PROBE, str(installed)],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    status = report["status"]
    assert status["available"] is True, status["error"]
    assert Path(status["loaded_from"]).resolve() == (installed / "agent_security_guard").resolve()
    # The full policy decided, not the degraded fallback: a write to the
    # guard's own code is denied and goes to the person for an explicit order.
    decision = report["decision"]
    assert decision["decision"] == "deny"
    assert decision["reason_code"] == "SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER"
    assert decision["action"] == "approve"

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


_RELOAD_PROBE = r"""
import importlib.util, json, re, sys
from pathlib import Path
plugin_dir = Path(sys.argv[1])

def load():
    # What Hermes does on a reload: evict the plugin's own modules, load again.
    for key in [k for k in sys.modules if k == "guard_plugin" or k.startswith("guard_plugin.")]:
        del sys.modules[key]
    spec = importlib.util.spec_from_file_location(
        "guard_plugin", plugin_dir / "__init__.py",
        submodule_search_locations=[str(plugin_dir)])
    plugin = importlib.util.module_from_spec(spec)
    sys.modules["guard_plugin"] = plugin
    spec.loader.exec_module(plugin)
    return plugin

load()
before = sys.modules["agent_security_guard"].__version__
init = plugin_dir / "agent_security_guard" / "__init__.py"
init.write_text(re.sub(r'__version__ = "[^"]+"', '__version__ = "9.9.9"', init.read_text()))
plugin = load()
after = sys.modules["agent_security_guard"].__version__
same = load() is not None and sys.modules["agent_security_guard"].__version__
print(json.dumps({"before": before, "after": after, "same": same,
                  "available": plugin.guard_status()["available"]}))
"""


@pytest.mark.skipif(
    guard_plugin._SYSTEM_PACKAGE.exists(),
    reason="a system-wide package is installed and would be loaded first",
)
def test_a_reload_after_an_update_runs_the_new_engine(tmp_path):
    # Hermes reloads the plugin in the running gateway after an install or
    # update. The guard package kept in memory used to stay the old one, so
    # the gateway went on deciding with the old rules until restarted.
    installed = tmp_path / "plugins" / "agent-security-guard"
    shutil.copytree(PLUGIN_DIR, installed, ignore=shutil.ignore_patterns("__pycache__"))
    home = tmp_path / "home"
    home.mkdir()
    env = dict(os.environ)
    env.update({"HOME": str(home), "USERPROFILE": str(home), "XDG_STATE_HOME": str(tmp_path / "state")})
    result = subprocess.run(
        [sys.executable, "-I", "-c", _RELOAD_PROBE, str(installed)],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["before"] != "9.9.9"
    assert report["after"] == "9.9.9"
    assert report["same"] == "9.9.9"
    assert report["available"] is True


def test_a_package_the_host_imported_from_elsewhere_is_left_alone(tmp_path):
    import types

    from plugin import _loader

    elsewhere = tmp_path / "site-packages" / "agent_security_guard"
    elsewhere.mkdir(parents=True)
    (elsewhere / "__init__.py").write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    module = types.ModuleType("agent_security_guard")
    module.__file__ = str(elsewhere / "__init__.py")
    module.__version__ = "0.1.0"
    assert _loader._replaced_on_disk(module) is False

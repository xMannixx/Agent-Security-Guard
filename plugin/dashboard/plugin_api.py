"""Backend of the guard's Desktop page: three read-only routes.

Mounted by Hermes under ``/api/plugins/agent-security-guard-plugin/`` behind its
dashboard auth, and only when the plugin is in ``plugins.enabled``. Every route
is a GET and reads the audit trail; none changes the policy, the mode or the
trail, and none answers an approval.

- ``/status``    mode, version, and today's counts (asked, blocked, allowed)
- ``/decisions`` the newest decisions with their reasons (``?all=1`` for all,
                 ``?limit=N``, at most 200)
- ``/verify``    the hash-chain check of the audit trail
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter()

_PLUGIN_DIR = Path(__file__).resolve().parent.parent
_MODULE = "agent_security_guard_plugin_desktop_backend"


_loaded = None
_loading = threading.Lock()


def _plugin():
    """The guard plugin from its own folder, loaded once as a package.

    Loading it registers nothing: it finds the guard package the same way the
    hooks do, from the same locations and with the same refusals. Requests
    arrive on several threads at once; the lock keeps a second one from using
    the module while the first is still running it.
    """
    global _loaded
    with _loading:
        if _loaded is None:
            spec = importlib.util.spec_from_file_location(
                _MODULE, str(_PLUGIN_DIR / "__init__.py"),
                submodule_search_locations=[str(_PLUGIN_DIR)],
            )
            if spec is None or spec.loader is None:
                raise ImportError(f"{_PLUGIN_DIR} is not a package")
            module = importlib.util.module_from_spec(spec)
            sys.modules[_MODULE] = module
            try:
                spec.loader.exec_module(module)
            except BaseException:
                sys.modules.pop(_MODULE, None)
                raise
            _loaded = module
        return _loaded


def _guard():
    """The guard package, its configuration, and the page helpers."""
    try:
        plugin = _plugin()
        with _loading:
            ui = importlib.import_module(_MODULE + "._ui")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"guard plugin not loadable: {exc}")
    status = plugin.guard_status()
    if not status.get("available"):
        raise HTTPException(status_code=503, detail=f"guard package unavailable: {status.get('error')}")
    package = sys.modules["agent_security_guard"]
    path = plugin._config_path()
    try:
        config, config_error = package.load_config(path), None
    except Exception as exc:  # the hooks enforce the defaults then, and so does the page
        config, config_error = package.load_config(None), f"{path}: {exc}"
    return package, config, config_error, path, ui


@router.get("/status")
def status():
    package, config, config_error, path, ui = _guard()
    result = ui.status(package, config)
    result["config_path"] = path
    result["config_error"] = config_error
    # Whether the page may switch the mode (it does so over plugin RPC, not here).
    mode = importlib.import_module(_MODULE + "._mode")
    result["mode_locked"], result["mode_file"] = mode.describe(_plugin())
    result["modes"] = list(mode.MODES)
    return result


@router.get("/decisions")
def decisions(limit: int = 50, all: int = 0):  # noqa: A002 (query parameter name)
    package, config, _error, _path, ui = _guard()
    return {"decisions": ui.decisions(package, config, limit=limit, attention_only=not all)}


@router.get("/verify")
def verify():
    package, config, _error, _path, ui = _guard()
    return ui.verify(package, config)

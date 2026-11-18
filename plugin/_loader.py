"""Finding and loading the guard package the plugin runs on.

Part of the plugin's entry point (``__init__.py``), kept apart so each file
does one thing. ``__init__`` imports everything it needs from here.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import stat
import sys
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("agent_security_guard_plugin")

_PACKAGE = "agent_security_guard"
_PLUGIN_DIR = Path(__file__).resolve().parent
# For an install the agent cannot rewrite: owned by root, like the policy in
# /etc/agent-security-guard. Looked at first.
_SYSTEM_PACKAGE = Path("/usr/local/lib/agent-security-guard/src")


def _hermes_home() -> Path:
    """The Hermes home of this process: the active profile's, if Hermes says so.

    ``hermes_constants.get_hermes_home()`` follows ``HERMES_HOME`` and profiles;
    outside Hermes (tests, the CLI) it is ``~/.hermes``.
    """
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home())
    except Exception:
        return Path.home() / ".hermes"


def _package_locations() -> List[Path]:
    """Where a copy of the package may be, in the order they are tried.

    The last one is the copy shipped inside the plugin directory
    (``scripts/bundle_engine.py``). A catalog install checks out only this
    directory, so that copy is what it runs; an operator's root-owned install
    or a repository checkout still comes first.
    """
    return [
        _SYSTEM_PACKAGE,
        _PLUGIN_DIR.parent / "security" / "agent-security-guard" / "src",
        _hermes_home() / "agent-security-guard" / "src",
        _PLUGIN_DIR,
    ]


def _refusal(location: Path, name: str = _PACKAGE) -> Optional[str]:
    """Why the copy in ``location`` must not be loaded, or None.

    A copy any user of the machine can rewrite, or one that belongs to
    somebody else, is not the operator's guard. One the operator's own account
    can rewrite cannot be told from a legitimate install, and is accepted.
    """
    if os.name != "posix":
        return None
    for directory in (location, location / name):
        info = directory.stat()
        if info.st_mode & stat.S_IWOTH:
            return f"{directory} is writable by every user of this machine"
        if info.st_uid not in (0, os.getuid()):
            return f"{directory} belongs to another user"
    return None


def _load_package(location: Path, name: str = _PACKAGE) -> None:
    """Load the package from exactly this directory, leaving ``sys.path`` alone.

    The directory used to be put at the front of ``sys.path``. Every module
    name in it then came before the standard library for the whole host: a
    ``colorsys.py`` next to the package was what ``import colorsys`` found.
    Loaded by its file, the package is the only thing that comes from there.
    """
    package_dir = location / name
    spec = importlib.util.spec_from_file_location(
        name, str(package_dir / "__init__.py"),
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"{package_dir} is not a package")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        for loaded in [key for key in sys.modules if key == name or key.startswith(name + ".")]:
            del sys.modules[loaded]
        raise


_load_notes: List[str] = []


def _find_package() -> None:
    """Have the package loaded from the first usable location.

    Without one, the import below is left to whatever the interpreter finds:
    an installed package.
    """
    if _PACKAGE in sys.modules:  # the host imported it itself
        return
    *installed, bundled = _package_locations()
    present = [loc for loc in installed if (loc / _PACKAGE / "__init__.py").is_file()]
    # The copy inside the plugin directory is for an install that has no
    # other one (the catalog's). Where an installed copy exists but is
    # refused or broken, the guard does not quietly switch to another
    # version: it reports it and runs on the degraded rules, as before.
    for location in present or [bundled]:
        if not (location / _PACKAGE / "__init__.py").is_file():
            continue
        try:
            refusal = _refusal(location)
            if refusal:
                _load_notes.append(f"not loaded from {location}: {refusal}")
                logger.error("guard package %s", _load_notes[-1])
                continue
            _load_package(location)
            return
        except Exception as exc:
            _load_notes.append(f"not loaded from {location}: {exc}")
            logger.warning("guard package %s", _load_notes[-1])

"""Changing the guard's mode from the Desktop page.

Reached only through the plugin RPC method ``plugin.<id>.mode.set``
(``ctx.register_rpc``). Hermes serves that to clients its gateway
authenticated, never to an anonymous HTTP request, and an agent's tool call is
not such a client. The change is written where the hooks read the policy, so
it lasts across restarts, and the hooks pick it up at their next call
(``_get_adapter``). Every change is recorded in the audit trail.

It refuses where the mode is not the user's to change from here:

- a root-owned policy in ``/etc/agent-security-guard`` is in force (that is
  the operator's lock against the agent, and the page must not route around
  it);
- ``AGENT_SECURITY_GUARD_MODE`` is set, which wins over any file;
- the policy file is a link, or would not load with the new mode.

Only the top-level ``mode:`` line is replaced; every other line of the file,
comments included, stays as it was.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

MODES = ("monitor", "autonomous-safe", "strict")
_STRENGTH = {mode: rank for rank, mode in enumerate(MODES)}

# A top-level `mode:` line: no indentation, an optional trailing comment kept.
_MODE_LINE = re.compile(r"^mode[ \t]*:[^\n#]*?(?P<comment>[ \t]+#[^\n]*)?[ \t]*$", re.MULTILINE)


class ModeRefused(Exception):
    """The mode cannot be changed from the Desktop page; the text says why."""


def weaker(new: str, old: Optional[str]) -> bool:
    """Whether ``new`` stops less than ``old``."""
    return _STRENGTH.get(new, 0) < _STRENGTH.get(str(old or ""), len(MODES))


def with_mode(text: str, mode: str) -> str:
    """``text`` with its top-level ``mode:`` set to ``mode``, or one added."""
    if mode not in MODES:
        raise ModeRefused(f"unknown mode {mode!r}; one of {', '.join(MODES)}")
    lines = _MODE_LINE.findall(text)
    if len(lines) > 1:
        raise ModeRefused("guard.yaml has more than one top-level mode line; change it by hand")
    if lines:
        return _MODE_LINE.sub(lambda m: f"mode: {mode}{m.group('comment') or ''}", text, count=1)
    separator = "" if not text or text.endswith("\n") else "\n"
    return f"{text}{separator}mode: {mode}\n"


def locked(plugin, environ=None) -> Optional[str]:
    """Why the mode cannot be changed here, or None."""
    environ = os.environ if environ is None else environ
    if str(environ.get("AGENT_SECURITY_GUARD_MODE", "") or "").strip():
        return "AGENT_SECURITY_GUARD_MODE is set and decides the mode"
    system = Path(plugin._SYSTEM_CONFIG)
    if system.is_file():
        return f"the system policy {system} decides the mode"
    return None


def target(plugin) -> Path:
    """The file the hooks read the policy from, or the Hermes home's guard.yaml."""
    active = plugin._config_path()
    return Path(active) if active else plugin._hermes_home() / "guard.yaml"


def set_mode(plugin, package, mode: Any, origin: str = "desktop") -> Dict[str, Any]:
    """Write ``mode`` to the policy file and record the change. Raises ModeRefused."""
    mode = str(mode or "").strip()
    if mode not in MODES:
        raise ModeRefused(f"unknown mode {mode!r}; one of {', '.join(MODES)}")
    reason = locked(plugin)
    if reason:
        raise ModeRefused(reason)
    path = target(plugin)
    if path.is_symlink():
        raise ModeRefused(f"{path} is a link; change the mode in the file it points to by hand")

    old_text = path.read_text(encoding="utf-8") if path.is_file() else ""
    try:
        old_mode = package.load_config(str(path) if path.is_file() else None).mode
    except Exception:
        old_mode = None
    new_text = with_mode(old_text, mode)
    if new_text != old_text:
        _write_checked(package, path, new_text, mode)
    # The hooks look at the file at most once a second; in this process,
    # make the next call look now.
    if hasattr(plugin, "_stamp_checked_at"):
        plugin._stamp_checked_at = 0.0

    _record(package, path, old_mode, mode, origin)
    return {"mode": mode, "previous": old_mode, "path": str(path)}


def _write_checked(package, path: Path, text: str, mode: str) -> None:
    """Write next to the file, load it as the guard would, then put it in place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    keep = (path.stat().st_mode & 0o777) if path.is_file() else 0o600
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, keep)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        loaded = package.load_config(str(temporary))
        if loaded.mode != mode:
            raise ModeRefused(f"guard.yaml would load with mode {loaded.mode!r}, not {mode!r}")
        os.replace(str(temporary), str(path))
    except ModeRefused:
        _remove(temporary)
        raise
    except Exception as exc:
        _remove(temporary)
        raise ModeRefused(f"guard.yaml with the new mode does not load: {exc}") from exc


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _record(package, path: Path, old: Optional[str], new: str, origin: str) -> None:
    """One audit record per change, in the trail the hooks write."""
    try:
        config = package.load_config(str(path))
        event = package.GuardEvent(
            ts=datetime.now(timezone.utc).isoformat(),
            event_type="mode_change",
            decision="allow",
            reason_code="MODE_CHANGED_BY_USER",
            source=origin,
            message=f"mode {old or '?'} -> {new} ({origin})",
        )
        audit = package.AuditLog(config=config)
        try:
            audit.record(event)
        finally:
            audit.close()
    except Exception:  # the change is made; a trail that cannot be written must not undo it
        pass


def rpc_handler(plugin_getter, package_getter):
    """The ``mode.set`` RPC handler: ``{"mode": ...}`` in, the result or an error out."""

    def handle(params, *, session_id=None, **_kwargs):
        params = params if isinstance(params, dict) else {}
        try:
            return set_mode(plugin_getter(), package_getter(), params.get("mode"))
        except ModeRefused as exc:
            return {"error": str(exc)}

    return handle


def describe(plugin) -> Tuple[Optional[str], Optional[str]]:
    """``(lock reason, file)`` for the page."""
    try:
        return locked(plugin), str(target(plugin))
    except Exception as exc:
        return f"cannot tell where the policy is: {exc}", None

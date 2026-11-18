"""AgentSecurityGuard plugin for Hermes / OpenClaw.

Two hooks, registered defensively (a hook must never crash the host):

- ``pre_llm_call``  -> wraps untrusted items into safe data blocks so web/tool
  content enters the prompt as DATA, not instructions (Enforcement of input
  hygiene).
- ``pre_tool_call`` -> runs the action + sequence policy and returns a
  machine-readable decision the host can enforce (allow / deny / transform /
  require_confirmation).

Host contract (kwargs are best-effort; unknown shapes are ignored):
- untrusted items: ``untrusted_items=[{content, source, channel, metadata}]``
- planned action: ``action={kind,target,method,...}``, or the tool call as the
  host has it: ``tool_name``+``args`` (Hermes), ``name``+``input``,
  ``function``+``arguments``, or the whole call as one mapping or object under
  ``tool_call`` / ``tool_use`` / ``function_call``. Plus optional provenance
  ``origin_trust``, ``data_sensitivity``, ``user_intent_origin``, ``chain_id``.
  A call that names no tool in any of these shapes is not evaluated, and that
  is logged; it is blocked under ``on_error: deny_all`` and asked about in
  ``strict`` mode (``_unreadable_call``).
- memory write: the lane and the source, as ``desired_memory_lane`` /
  ``memory_source`` in ``action``, or in ``args`` under the names memory tools
  use (``lane``, ``memory_lane``, ``source``).

What Hermes actually sends and reads (checked against its plugin dispatcher):
- ``pre_tool_call`` gets ``tool_name``, ``args`` and ids (``session_id``,
  ``turn_id``, ...), no provenance. Of the result it reads only ``action``:
  ``block`` vetoes the call, ``approve`` sends it to the human-approval gate.
  A result without ``action`` is ignored, so every non-allow decision carries
  one (see ``_with_host_directive``).
- ``pre_llm_call`` gets the user's message and ids, never ``untrusted_items``,
  so the wrapper above has nothing to wrap there.
- ``transform_tool_result`` gets each finished tool result before it enters the
  model's context and takes a returned string as its replacement. That is where
  web content arrives in Hermes, so that is where it is wrapped
  (``wrap_tool_result``).
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("agent_security_guard_plugin")

# Hermes loads this file as a package. A tool that imports it as a single file
# (pytest run in an installed copy, whose folder name is not a Python name)
# gives it no package; then it is made one, over its own folder only.
if not __package__:
    __path__ = [os.path.dirname(os.path.abspath(__file__))]
    __package__ = __name__
    if __spec__ is not None:
        __spec__.submodule_search_locations = __path__

# The parts of the entry point, one file each. Everything is imported back
# here, so ``plugin.<name>`` keeps working for Hermes and the tests.
from ._loader import (  # noqa: E402,F401
    _PACKAGE,
    _PLUGIN_DIR,
    _SYSTEM_PACKAGE,
    _find_package,
    _hermes_home,
    _load_notes,
    _load_package,
    _package_locations,
    _refusal,
)
from ._fallback import (  # noqa: E402,F401
    _CODE_TOOLS,
    _DANGEROUS_KIND_TOKENS,
    _FALLBACK_BEGIN,
    _FALLBACK_DATA_MARKER,
    _FALLBACK_END,
    _FALLBACK_FRAME_MARKER,
    _STATE_CHANGING_ACTIONS,
    _STATE_CHANGING_KIND_NAMES,
    _UNTRUSTED_CONTENT_TOOLS,
    _acts_by_argument,
    _fail_closed_payload,
    _fallback_block,
    _is_dangerous_by_name,
    _untrusted_content_tool_by_name,
)
from ._calls import (  # noqa: E402,F401
    _MEMORY_LANE_KEYS,
    _MEMORY_SOURCE_KEYS,
    _PAYLOAD_KEYS,
    _TARGET_KEYS,
    _TOOL_ARGS_KEYS,
    _TOOL_CALL_KEYS,
    _TOOL_NAME_KEYS,
    _arguments,
    _enum,
    _extract_untrusted_items,
    _field,
    _first,
    _stated_lane,
    _stated_source,
    _tool_call,
    _with_positional,
    _workspace_root,
)
from ._mode import rpc_handler as _rpc_handler  # noqa: E402
from ._decisions import (  # noqa: E402,F401
    _APPROVED_PER_CALL,
    _NEEDS_USER_ORDER,
    _call_fingerprint,
    _enforcement_payload,
    _with_host_directive,
)


_find_package()

_IMPORT_ERROR: Optional[str] = None
try:
    from agent_security_guard import (  # noqa: E402
        AgentAction,
        AuditLog,
        DataSensitivity,
        GuardContext,
        GuardAdapter,
        OriginTrust,
        UserIntentOrigin,
        brings_untrusted_content,
        classify_action,
        detect_no_write_scope,
        is_short_confirmation,
        is_state_changing,
        load_config,
        normalize_action,
    )
except Exception as exc:  # pragma: no cover - exercised only on broken installs
    logger.warning("agent-security-guard import failed: %s", exc)
    _IMPORT_ERROR = "; ".join([str(exc)] + _load_notes)
    GuardAdapter = None  # type: ignore
    # Stand-in so the hook can still describe the call and reach the degraded
    # decision; without it _extract_action raised NameError instead.
    from types import SimpleNamespace as AgentAction  # type: ignore


try:
    # The plugin and the package, in every place it may be loaded from, are
    # the guard's own code. A file tool writing there is not an ordinary
    # write, also where nothing is installed yet: a copy planted in a location
    # that is tried earlier would be the guard at the next start.
    from agent_security_guard import protect_guard_files  # noqa: E402

    protect_guard_files(
        _PLUGIN_DIR, *(location / _PACKAGE for location in _package_locations())
    )
except Exception as exc:  # an older package, or none at all
    logger.warning("guard files are not protected from file tools: %s", exc)


_adapter = None
_config = None
_config_error: Optional[str] = None
# The policy file the adapter was built from, as (path, mtime, size). A change
# (the Desktop page switching the mode, or an edit by hand) is picked up at the
# next hook call instead of at the next restart of the gateway.
_config_stamp: Optional[tuple] = None

_SYSTEM_CONFIG = Path("/etc/agent-security-guard/guard.yaml")


def _config_path() -> Optional[str]:
    """First guard.yaml found in the operator's locations, else None (defaults).

    The working directory is deliberately not searched. It is the agent's
    workspace: a cloned repository, or the agent itself, could place a
    guard.yaml there and switch the guard off with ``mode: monitor``.
    """
    for candidate in (
        _SYSTEM_CONFIG,
        _hermes_home() / "guard.yaml",
        Path(__file__).resolve().parent.parent / "guard.yaml",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def _warn_if_workspace_config_ignored(chosen: Optional[str]) -> None:
    """Say so when a guard.yaml in the working directory is not being used.

    Up to 0.3.0 that file was loaded first, so an operator may still keep the
    policy there; dropping it without a word would quietly change their setup.
    """
    try:
        stray = Path.cwd() / "guard.yaml"
        if stray.is_file() and not (chosen and stray.samefile(chosen)):
            logger.warning(
                "%s is ignored: the policy is not read from the working "
                "directory. Move it to %s or %s.",
                stray, _SYSTEM_CONFIG, _hermes_home() / "guard.yaml",
            )
    except OSError:
        pass


def _policy_stamp() -> Optional[tuple]:
    try:
        path = _config_path()
    except Exception:
        return None
    if path is None:
        return (None,)
    try:
        info = os.stat(path)
    except OSError:
        return (path,)
    return (path, info.st_mtime_ns, info.st_size)


_adapter_lock = threading.Lock()
_STAMP_INTERVAL = 1.0
_stamp_checked_at = 0.0


def _get_adapter():
    """The guard, built from the policy file; rebuilt when that file changes."""
    if GuardAdapter is None:
        return None
    global _stamp_checked_at
    current = _adapter
    if current is not None:
        # Looking at the file costs more than deciding a call; once a second
        # is soon enough for a change the person made by hand or on the page.
        now = time.monotonic()
        if now - _stamp_checked_at < _STAMP_INTERVAL:
            return current
        _stamp_checked_at = now
        if _policy_stamp() == _config_stamp:
            return current
    with _adapter_lock:
        if _adapter is not None and _adapter is not current and _policy_stamp() == _config_stamp:
            return _adapter  # another thread has just rebuilt it
        return _build_adapter(_adapter)


def _build_adapter(previous):
    global _adapter, _config, _config_error, _config_stamp
    if previous is not None:
        logger.warning("guard policy changed (%s); loading it", _config_path())
    _config_stamp = _policy_stamp()
    path = None
    try:
        path = _config_path()
        _warn_if_workspace_config_ignored(path)
        _config = load_config(path)
        _config_error = None
    except Exception as exc:
        # An unusable policy file must neither take the host down (0.2.x)
        # nor leave it unguarded (0.3.0 skipped evaluation entirely): keep
        # evaluating on the built-in defaults and report the error.
        _config_error = f"{path}: {exc}"
        logger.error(
            "guard.yaml unusable (%s); enforcing built-in defaults", _config_error
        )
        _config = load_config(None)
    # An unwritable audit sink must not cost the host its guard: audit is
    # observability, not enforcement, so run without it if it cannot open.
    audit = None
    try:
        audit = AuditLog(config=_config)
    except Exception as exc:
        logger.warning("audit log unavailable; continuing without it: %s", exc)
    try:
        # What the turns so far have read stays known across a rebuild: a
        # changed mode must not forget outside content already in a turn.
        history = previous.history if previous is not None else None
        adapter = GuardAdapter(config=_config, audit=audit, history=history)
    except Exception as exc:
        logger.warning("GuardAdapter init failed: %s", exc)
        return previous
    _adapter = adapter
    if previous is not None and previous.audit is not None:
        try:
            previous.audit.close()  # reopens by itself if a call still in flight writes
        except Exception:
            pass
    if adapter.mode_source == "env":
        logger.warning("mode '%s' forced by AGENT_SECURITY_GUARD_MODE", adapter.mode)
    return adapter


# The Desktop page's mode switch (``_mode``), reached through plugin RPC.
_mode_rpc = _rpc_handler(lambda: sys.modules[__name__], lambda: sys.modules[_PACKAGE])


def register(ctx) -> None:
    """Entry point Hermes calls to wire the hooks."""
    ctx.register_hook("pre_llm_call", wrap_untrusted_context)
    ctx.register_hook("pre_tool_call", guard_tool_call)
    # The Desktop page switches the mode through this method; Hermes serves it
    # only to clients its gateway authenticated. Older hosts have no plugin RPC.
    register_rpc = getattr(ctx, "register_rpc", None)
    if callable(register_rpc):
        try:
            register_rpc("mode.set", _mode_rpc)
        except Exception as exc:
            logger.warning("mode.set RPC not registered: %s", exc)
    try:
        ctx.register_hook("transform_tool_result", wrap_tool_result)
    except Exception as exc:  # a host without this hook must keep the other two
        logger.warning("transform_tool_result hook not registered: %s", exc)


def wrap_tool_result(**kwargs) -> Optional[str]:
    """Wrap the result of a web, search or browser tool as a data block.

    Hermes calls ``transform_tool_result`` with each finished result before it
    enters the model's context and takes a returned string as the replacement;
    ``None`` leaves the result as it is. Only string results of tools that
    return outside content are touched, and not in ``monitor`` mode, which
    changes nothing about the host.

    If wrapping fails, the content still does not go through raw: it gets the
    degraded wrapper.
    """
    result = kwargs.get("result")
    call = _tool_call(kwargs)
    if not isinstance(result, str) or not result or call is None:
        return None
    tool_name, tool_args = call
    try:
        adapter = _get_adapter()
        if adapter is None:
            return _fallback_block(result) if _untrusted_content_tool_by_name(tool_name) else None
        if adapter.mode == "monitor" or not adapter.config.wrap_tool_results:
            return None
        action = _extract_action(kwargs)
        if action is None or not brings_untrusted_content(
            normalize_action(action), adapter.config
        ):
            return None
        metadata: Dict[str, Any] = {"source_kind": "web_fetch"}
        where = _first(tool_args, ("url", "urls", "query", "q"))
        if isinstance(where, (list, tuple)):
            where = ", ".join(str(item) for item in where)
        if where:
            metadata["url"] = str(where)
        # clip=False: Hermes has already sized the result; cutting it here
        # would cost the agent the rest of the page.
        _report, block = adapter.guard_input(result, tool_name, "tool", metadata, clip=False)
        return block
    except Exception as exc:
        logger.warning("wrapping the result of %s failed; using degraded wrapper: %s", tool_name, exc)
        return _fallback_block(result) if _untrusted_content_tool_by_name(tool_name) else None


def wrap_untrusted_context(**kwargs) -> Optional[Dict[str, Any]]:
    """Wrap untrusted items into safe data blocks for the prompt.

    Fail-closed: if the guard is unavailable or wrapping an item raises, the
    raw untrusted content is never passed through. Each item is replaced with a
    degraded-but-safe data block instead of being silently dropped.
    """
    _remember_turn_scope(kwargs)
    items = _extract_untrusted_items(kwargs)
    if not items:
        return None
    adapter = _get_adapter()
    blocks: List[str] = []
    for item in items:
        content = item.get("content", "")
        try:
            if adapter is None:
                raise RuntimeError(_IMPORT_ERROR or "guard adapter unavailable")
            _report, block = adapter.guard_input(
                content,
                item.get("source", "unknown"),
                item.get("channel", "unknown"),
                item.get("metadata"),
            )
            blocks.append(block)
        except Exception as exc:
            logger.warning("guard_input failed; using degraded wrapper: %s", exc)
            blocks.append(_fallback_block(content))
    if not blocks:
        return None
    return {"context": "\n\n".join(blocks)}


def guard_tool_call(*positional, **kwargs) -> Optional[Dict[str, Any]]:
    """Evaluate a planned tool call; return a decision dict for the host.

    When the guard cannot evaluate the action (import/init failure or a runtime
    exception) it degrades instead of denying everything: reads and
    unrecognized host tools keep working, flagged, while state-changing and
    dangerous kinds are blocked. A guard that takes the whole host down when
    its own audit file is unwritable is not a security control, it is an
    outage; one that waves a write through because evaluating it raised is not
    one either. Set ``on_error: deny_all`` in guard.yaml to block everything.
    """
    kwargs = _with_positional(positional, kwargs)
    action = _extract_action(kwargs)
    if action is None:
        return _unreadable_call(kwargs)
    fingerprint = _call_fingerprint(kwargs)
    adapter = _get_adapter()
    if adapter is None:
        return _with_host_directive(
            _degraded_payload(
                action, _IMPORT_ERROR or "guard adapter unavailable", config=_config
            ),
            fingerprint,
        )
    try:
        context = _extract_context(kwargs, adapter)
        decision = adapter.guard_action(action, context)
    except Exception as exc:
        logger.warning("guard_action failed; degrading: %s", exc)
        return _with_host_directive(
            _degraded_payload(
                action,
                f"guard evaluation error: {exc}",
                config=adapter.config,
                mode=getattr(adapter, "mode", None),
            ),
            fingerprint,
        )
    payload = _enforcement_payload(decision)
    if _config_error:
        payload["config_error"] = _config_error
    trusted_origin = (
        not context.origin_trust.is_untrusted
        and context.user_intent_origin is not UserIntentOrigin.UNTRUSTED_SUGGESTION
    )
    return _with_host_directive(
        payload, fingerprint, trusted_origin, str(getattr(action, "kind", "") or "")
    )


_UNREADABLE = "GUARD_UNREADABLE_CALL"
_unreadable_calls = 0
_unreadable_shapes: set = set()
_MAX_REPORTED_SHAPES = 32


def _unreadable_call(kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The hook was called and nothing in the call says which tool is meant.

    This used to return ``None`` without a word. To a host that hands its
    calls over in a shape the guard does not know, every call was "no
    objection", and nothing said that the guard was not looking at any of
    them. It is still not an outage by default: the guard cannot tell a read
    from a write here, and blocking what it cannot read is how 0.2.x took
    hosts down. But it is said, once per shape, and counted; the operator who
    asked for everything to be blocked when the guard cannot evaluate
    (``on_error: deny_all``) gets that, and ``strict`` mode asks.
    """
    global _unreadable_calls
    _unreadable_calls += 1
    shape = tuple(sorted(str(key) for key in kwargs))
    if shape not in _unreadable_shapes and len(_unreadable_shapes) < _MAX_REPORTED_SHAPES:
        _unreadable_shapes.add(shape)
        logger.error(
            "pre_tool_call names no tool in a shape the guard reads (arguments "
            "given: %s). Calls of this shape are NOT evaluated. Pass tool_name "
            "and args, or set on_error: deny_all to block them.",
            ", ".join(shape) or "none",
        )
    adapter = _get_adapter()
    config = adapter.config if adapter is not None else _config
    mode = getattr(adapter, "mode", None)
    if mode == "monitor":
        return None
    message = (
        "agent-security-guard could not read this tool call (it names no tool "
        "in a shape the guard knows), so it was not evaluated."
    )
    if str(getattr(config, "on_error", "degrade") or "degrade").lower() == "deny_all":
        payload = _fail_closed_payload(message)
        payload["reason_code"] = _UNREADABLE
        return _with_host_directive(payload, "")
    if mode == "strict":
        payload = _fail_closed_payload(message)
        payload.update(
            decision="require_confirmation", reason_code=_UNREADABLE,
            requires_confirmation=True, risk_score=0.6,
        )
        return _with_host_directive(payload, "")
    return None


def _blocked_while_degraded(action) -> bool:
    """Whether an action the engine could not evaluate is held back.

    Held back: kinds dangerous by name and everything state-changing. Those are
    what the engine can deny, so letting them through unevaluated made any
    error a caller could provoke a way around the denial. Reads and
    unrecognized host tools pass.
    """
    kind = str(getattr(action, "kind", "") or "").strip().lower()
    if _is_dangerous_by_name(kind) or kind in _STATE_CHANGING_KIND_NAMES:
        return True
    if _acts_by_argument(kind, getattr(action, "metadata", None)):
        return True
    if GuardAdapter is None:
        return False
    try:
        # What a name cannot tell: a generic request carrying a write method,
        # a tool the operator declared, a namespaced tool name.
        return is_state_changing(classify_action(normalize_action(action), _config))
    except Exception:
        return True


def _degraded_payload(action, message: str, config=None, mode=None) -> Dict[str, Any]:
    """Decision used when the policy engine itself could not run.

    ``on_error: deny_all`` restores hard fail-closed. The default keeps reads
    and unrecognized host tools (listings, dashboards) working, loudly flagged
    as ``degraded``, and blocks dangerous and state-changing kinds. ``monitor``
    mode never blocks, here as everywhere else.
    """
    on_error = str(getattr(config, "on_error", "degrade") or "degrade").lower()
    kind = getattr(action, "kind", "") or ""
    blocking = mode != "monitor"
    if blocking and on_error == "deny_all":
        return _fail_closed_payload(message)
    if blocking and _blocked_while_degraded(action):
        payload = _fail_closed_payload(message)
        payload["reason_code"] = "GUARD_DEGRADED_DANGEROUS_KIND"
        payload["message"] = (
            f"{message}; '{kind}' is dangerous by name or changes state and is "
            "blocked while the guard is unavailable."
        )
        return payload
    return {
        "decision": "allow_with_warning",
        "reason_code": "GUARD_DEGRADED_ALLOWED",
        "message": (
            f"{message}; action '{kind}' allowed unevaluated so the host keeps "
            "working. Fix the guard installation or set on_error: deny_all."
        ),
        "transformed_action": None,
        "audit_required": True,
        "risk_score": 0.5,
        "allowed": True,
        "requires_confirmation": False,
        "block": False,
        "degraded": True,
    }


# --------------------------------------------------------------------------- #
# kwargs extraction (best-effort, host-agnostic)
# --------------------------------------------------------------------------- #


def _extract_action(kwargs: Dict[str, Any]):
    spec = kwargs.get("action")
    if isinstance(spec, dict):
        return AgentAction(
            kind=spec.get("kind", ""),
            target=spec.get("target", ""),
            method=spec.get("method"),
            payload=spec.get("payload"),
            desired_memory_lane=spec.get("desired_memory_lane"),
            memory_source=spec.get("memory_source"),
            metadata=spec.get("metadata", {}) or {},
        )
    call = _tool_call(kwargs)
    if call is not None:
        tool_name, args = call
        return AgentAction(
            kind=tool_name,
            target=str(_first(args, _TARGET_KEYS) or ""),
            method=args.get("method"),
            payload=_first(args, _PAYLOAD_KEYS),
            desired_memory_lane=_stated_lane(args),
            memory_source=_stated_source(args),
            # The model writes the arguments; it must not get to say which
            # chain the call belongs to and so leave the one it is in.
            metadata={k: v for k, v in args.items() if k != "chain_id"},
        )
    return None


def _extract_context(kwargs: Dict[str, Any], adapter) -> GuardContext:
    config = adapter.config
    no_write, short_conf = _scope_flags(kwargs, config)
    sensitivity = _enum(DataSensitivity, kwargs.get("data_sensitivity"), None)
    return GuardContext(
        mode=adapter.mode,
        # A host that states no provenance gets UNSPECIFIED, not UNKNOWN.
        # UNKNOWN counts as untrusted, which denied the host's own shell,
        # install, and config operations for simply not passing a kwarg.
        origin_trust=_enum(
            OriginTrust, kwargs.get("origin_trust"), OriginTrust.UNSPECIFIED
        ),
        # Hermes passes none. Decisions take PUBLIC then, the audit trail
        # records that nothing was stated.
        data_sensitivity=DataSensitivity.PUBLIC if sensitivity is None else sensitivity,
        data_sensitivity_stated=sensitivity is not None,
        user_intent_origin=_enum(UserIntentOrigin, kwargs.get("user_intent_origin"), UserIntentOrigin.UNKNOWN),
        current_channel=kwargs.get("channel", ""),
        # Hermes sends no chain_id but a turn_id: one user turn is one chain.
        chain_id=kwargs.get("chain_id") or kwargs.get("turn_id") or None,
        workspace_root=_workspace_root(kwargs),
        domain_allowlist=config.domain_allowlist,
        config=config,
        no_write_scope_active=no_write,
        short_confirmation=short_conf,
        previous_action_was_explicitly_authorized=bool(
            kwargs.get("previous_action_authorized", False)
        ),
        requested_action_from_nonuser_context=bool(
            kwargs.get("action_from_nonuser_context", False)
        ),
    )


def _scope_flags(kwargs: Dict[str, Any], config=None) -> tuple:
    """Resolve no-write-scope / short-confirmation flags.

    Explicit kwargs always win. Deriving them from raw ``user_message`` text is
    OFF unless the operator opts in (``scope_from_text: true``, or a per-call
    ``scope_from_text=True``): inferring intent from wording meant an everyday
    "ok" or "zeig mir das Dashboard, nur lesen" denied every state-changing
    action in the turn.
    """
    no_write = kwargs.get("no_write_scope")
    short_conf = kwargs.get("short_confirmation")
    if no_write is not None and short_conf is not None:
        return bool(no_write), bool(short_conf)

    opt_in = kwargs.get("scope_from_text")
    if opt_in is None:
        opt_in = bool(getattr(config, "scope_from_text", False))
    user_message = kwargs.get("user_message") or ""
    if opt_in and isinstance(user_message, str) and user_message:
        if no_write is None:
            no_write = detect_no_write_scope(user_message)
        if short_conf is None:
            short_conf = is_short_confirmation(user_message)
    elif opt_in:
        remembered = _turn_scopes.get(kwargs.get("session_id"))
        if remembered is not None:
            if no_write is None:
                no_write = remembered[0]
            if short_conf is None:
                short_conf = remembered[1]
    return bool(no_write), bool(short_conf)


# Hermes hands the user's message to pre_llm_call only, the tool calls of that
# turn arrive without it. What the message says about scope is kept per session
# (the two flags, not the text) for the opt-in scope_from_text check.
_turn_scopes: "OrderedDict[str, tuple]" = OrderedDict()
_turn_scopes_lock = threading.Lock()
_MAX_REMEMBERED_SESSIONS = 256


def _remember_turn_scope(kwargs: Dict[str, Any]) -> None:
    session, message = kwargs.get("session_id"), kwargs.get("user_message")
    if GuardAdapter is None or not isinstance(session, str) or not session:
        return
    if not isinstance(message, str):
        return
    # Only the opt-in scope_from_text check reads these flags: without it,
    # the message is not scanned at all.
    opt_in = kwargs.get("scope_from_text")
    if opt_in is None:
        adapter = _get_adapter()
        opt_in = adapter is not None and bool(getattr(adapter.config, "scope_from_text", False))
    if not opt_in:
        return
    flags = (detect_no_write_scope(message), is_short_confirmation(message))
    with _turn_scopes_lock:
        _turn_scopes[session] = flags
        _turn_scopes.move_to_end(session)
        while len(_turn_scopes) > _MAX_REMEMBERED_SESSIONS:
            _turn_scopes.popitem(last=False)


def guard_status() -> Dict[str, Any]:
    """Diagnostics. Never raises."""
    return {
        "available": GuardAdapter is not None,
        "error": _IMPORT_ERROR,
        # Calls to the tool hook that named no tool the guard could read.
        "unreadable_calls": _unreadable_calls,
        # Where the code in use came from.
        "loaded_from": os.path.dirname(
            getattr(sys.modules.get(_PACKAGE), "__file__", None) or ""
        ) or None,
        "config_error": _config_error,
        # None until the first hook call has created the adapter.
        "mode": getattr(_adapter, "mode", None),
        "mode_source": getattr(_adapter, "mode_source", None),
    }

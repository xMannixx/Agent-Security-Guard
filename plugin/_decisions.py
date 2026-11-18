"""Turning a guard decision into the result Hermes acts on.

Hermes reads ``action`` from a ``pre_tool_call`` result: ``block`` vetoes the
call, ``approve`` sends it to the human-approval gate.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from ._calls import _tool_call

# Denials that mean "the user has not ordered this", not "this is forbidden".
# A host with a human-approval gate can obtain exactly that order.
_NEEDS_USER_ORDER = frozenset({"SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER"})


_APPROVED_PER_CALL = ("SELF_MODIFICATION", "PRIVILEGED_MEMORY")


def _with_host_directive(
    payload: Dict[str, Any],
    fingerprint: str,
    trusted_origin: bool = False,
    kind: str = "",
) -> Dict[str, Any]:
    """Add the directive Hermes acts on to a non-allow decision.

    Hermes reads ``action`` from a ``pre_tool_call`` result and nothing else:
    ``block`` vetoes the call (``message`` becomes the tool result) and
    ``approve`` sends it to the human-approval gate, which fails closed when
    nobody can answer. A result without ``action`` is ignored, so ``decision``
    and ``block`` on their own never stopped anything there.

    A confirmation becomes ``approve``. So does the one denial that only says
    the user's order is missing, provided nothing untrusted proposed the call:
    Hermes cannot say who asked, and its approval prompt is that order.
    """
    if payload.get("allowed"):
        return payload
    reason = str(payload.get("reason_code") or "")
    if not payload.get("message"):
        payload["message"] = f"Blocked by agent-security-guard ({reason})."
    if payload.get("requires_confirmation") or (
        trusted_origin and reason in _NEEDS_USER_ORDER
    ):
        payload["action"] = "approve"
        # Hermes offers "always allow" per rule_key. For a self-modification
        # and for a write to privileged memory the key is tied to the exact
        # call, so one approval cannot cover a different patch or a different
        # rule later. Other confirmations are keyed by reason and tool, so the
        # user can settle "terminal after web content" once for the session
        # instead of at every command.
        scope = fingerprint if reason.startswith(_APPROVED_PER_CALL) else kind
        payload["rule_key"] = f"agent-security-guard:{reason}:{scope}"
    else:
        payload["action"] = "block"
    return payload


def _call_fingerprint(kwargs: Dict[str, Any]) -> str:
    """Short hash over the tool name and every argument of the call."""
    spec = kwargs.get("action")
    call = _tool_call(kwargs)
    subject: Any = spec if isinstance(spec, dict) else list(call or ())
    try:
        raw = json.dumps(subject, sort_keys=True, default=str)
    except Exception:  # unserializable or too deeply nested
        raw = call[0] if call else ""
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


def _enforcement_payload(decision) -> Dict[str, Any]:
    """Attach unambiguous enforcement flags to a decision dict.

    ``block`` is true for ANY non-allow decision (deny, require_confirmation,
    transform) so a host that only inspects ``block`` fails safe. Hosts that
    understand confirmations/transforms can use the explicit flags.
    """
    payload = decision.to_dict()
    value = decision.decision.value
    allowed = value in ("allow", "allow_with_warning")
    payload["allowed"] = allowed
    payload["requires_confirmation"] = value == "require_confirmation"
    payload["block"] = not allowed
    return payload

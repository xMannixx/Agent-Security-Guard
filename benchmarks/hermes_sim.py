"""Drive the plugin the way Hermes Agent drives it.

Hermes calls three hooks of the plugin. This module calls them with the keyword
arguments Hermes passes (hermes-agent 3b42157858, 2026-11-09) and reads the
results with Hermes's own rules:

- ``pre_llm_call``: ``session_id``, ``user_message``, ...
  (``agent/turn_context.py``)
- ``pre_tool_call``: ``tool_name``, ``args``, ``task_id``, ``session_id``,
  ``tool_call_id``, ``turn_id``, ``api_request_id``, ``middleware_trace``,
  ``conversation_id`` (``hermes_cli/plugins.py``,
  ``_get_pre_tool_call_directive_details``). A ``block`` with a message vetoes
  the call, ``approve`` sends it to the human-approval prompt, anything else
  lets it run. ``block`` wins over ``approve``.
- ``transform_tool_result``: the same ids plus ``result``; a returned string
  replaces the result the model sees (``model_tools.py``).

A turn id has Hermes's shape, ``<session>:<task>:<8 hex>``: one user turn is
one chain for the guard.
"""

from __future__ import annotations

import itertools
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

RUN, ASK, BLOCK = "run", "ask", "block"


def hermes_directive(result: Any) -> str:
    """What Hermes does with a ``pre_tool_call`` result."""
    if not isinstance(result, dict):
        return RUN
    action = result.get("action")
    message = result.get("message")
    if action == "block" and isinstance(message, str) and message:
        return BLOCK
    if action == "approve":
        return ASK
    return RUN


@dataclass
class Call:
    tool: str
    args: Dict[str, Any]
    outcome: str
    reason: Optional[str]
    seconds: float
    model_sees: Optional[str] = None


@dataclass
class Turn:
    session: "Session"
    turn_id: str
    task_id: str
    calls: List[Call] = field(default_factory=list)

    def tool(self, name: str, args: Dict[str, Any], result: Optional[str] = None) -> Call:
        plugin = self.session.plugin
        ids = dict(
            task_id=self.task_id,
            session_id=self.session.session_id,
            tool_call_id=f"call_{next(self.session.counter)}",
            turn_id=self.turn_id,
            api_request_id=f"req_{uuid.uuid4().hex[:12]}",
            conversation_id=self.session.session_id,
        )
        start = time.perf_counter()
        decision = plugin.guard_tool_call(
            tool_name=name, args=dict(args), middleware_trace=[], **ids
        )
        seconds = time.perf_counter() - start
        outcome = hermes_directive(decision)
        call = Call(
            tool=name,
            args=args,
            outcome=outcome,
            reason=(decision or {}).get("reason_code") if isinstance(decision, dict) else None,
            seconds=seconds,
        )
        if outcome == RUN and result is not None:
            start = time.perf_counter()
            replaced = plugin.wrap_tool_result(
                tool_name=name, args=dict(args), result=result,
                duration_ms=1, status="ok", error_type=None, error_message=None, **ids
            )
            call.seconds += time.perf_counter() - start
            call.model_sees = replaced if isinstance(replaced, str) else result
        self.calls.append(call)
        return call


class Session:
    def __init__(self, plugin) -> None:
        self.plugin = plugin
        self.session_id = f"bench_{uuid.uuid4().hex[:12]}"
        self.counter = itertools.count(1)

    def turn(self, user_message: str) -> Turn:
        task_id = str(uuid.uuid4())
        turn = Turn(self, f"{self.session_id}:{task_id}:{uuid.uuid4().hex[:8]}", task_id)
        self.plugin.wrap_untrusted_context(
            session_id=self.session_id, user_message=user_message,
            conversation_history=[], is_first_turn=False, model="bench", platform="cli",
        )
        return turn

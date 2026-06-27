# Self-Modification Governance (Host Integration Contract)

Patching a skill (`SKILL.md`), creating/deleting a skill, or approving a
procedural rule changes the agent's **future behavior**. That is more dangerous
than a normal file write, and it must never happen off untrusted content, off a
bare "yes", or under an explicit no-write scope.

ASG is the lock. **The host must route the door through it.** This document is
the contract.

## Two levels — and the honest boundary

1. **ASG library (enforced here):** `ActionTier.SELF_MODIFICATION`, the
   no-write-scope gate, the ambiguous-short-confirmation gate, the
   never-direct-allow rule, the two-phase reference gate, and regression +
   end-to-end tests.
2. **Hermes host / self-improvement pipeline (must be wired there):** the
   pipeline must stop writing `SKILL.md` directly and instead emit a guard
   action and obey the decision.

ASG cannot force the host to call it. If Hermes patches internally without a
guard call, `policy.py` can be perfect and the file still changes. Therefore the
real acceptance check lives in the host, against the criteria below.

## What the host MUST do

> This fix is only complete when Hermes self-improvement / skill-patch no longer
> writes directly, but always runs as
> `AgentAction(kind="skill_patch" | "self_improvement_patch")` through the Agent
> Security Guard:
>
> - the self-improvement patch creates a guard action
> - `pre_tool_call` / `check_action` is called
> - `no_write_scope_active=True` blocks the patch
> - `short_confirmation` without prior explicit authorization blocks the patch
> - guard unavailable blocks fail-closed
> - no direct bypass-write to `SKILL.md` is allowed
>
> `SELF_MODIFICATION` must never write through a single `require_confirmation`
> result. `require_confirmation` only produces a *pending intent* with an
> `action_hash`. A write may happen only when: (1) the user explicitly confirms
> this concrete patch, (2) the confirmation is bound to the same `action_hash`,
> (3) `no_write_scope_active` is still `False`, (4)
> `requested_action_from_nonuser_context` is `False`, and (5) the final guard
> check does not return `deny`. Ambiguous confirmations ("ja", "ok", "mach das")
> are not enough unless they refer unambiguously to a concrete patch shown
> immediately before, with an identical `action_hash`.

## Reference gate (copy this shape)

`agent_security_guard.self_improvement` is the canonical two-phase gate. Phase 1
proposes (writes nothing); phase 2 writes only on a hash-bound, guard-approved
confirmation.

```python
from agent_security_guard import (
    GuardAdapter, GuardContext, OriginTrust, UserIntentOrigin, Decision,
    propose, confirm,
)

adapter = GuardAdapter(audit=...)        # one per session

# Phase 1 — the agent wants to patch its own skill. NOTHING is written.
pending = propose(
    adapter,
    target="communication-style/SKILL.md",
    payload=new_skill_text,
    context=GuardContext(
        origin_trust=OriginTrust.TRUSTED_USER,
        user_intent_origin=UserIntentOrigin.HUMAN_EXPLICIT,  # never from a doc/tool
        no_write_scope_active=user_set_no_write_scope,
    ),
)
if pending.decision.decision is Decision.DENY:
    show_user(pending.decision.reason_code)   # e.g. EXPLICIT_NO_WRITE_SCOPE_VIOLATION
    return                                     # no write

# Show the concrete diff + pending.action_hash to the USER and get a real,
# specific confirmation ("yes, apply exactly this patch to <file>").

# Phase 2 — write only via the gate, bound to the same action_hash.
result = confirm(
    adapter,
    pending,
    confirmed_action_hash=pending.action_hash,   # must match
    context=GuardContext(
        origin_trust=OriginTrust.TRUSTED_USER,
        user_intent_origin=UserIntentOrigin.HUMAN_CONFIRMATION,
        previous_action_was_explicitly_authorized=True,
        requested_action_from_nonuser_context=False,
    ),
    writer=lambda action: Path(action.target).write_text(action.payload, "utf-8"),
)
assert result.written is True   # only when the guard approved AND the hash matched
```

Fail-closed by construction: a `require_confirmation` alone never writes; a
`deny`, a guard error/unavailability, or an `action_hash` mismatch never writes.

## Mapping host signals to `GuardContext`

| Host situation | Field to set |
|---|---|
| User said "nur Vorschlag / keine Datei ändern / keinen Patch" | `no_write_scope_active=True` |
| Last user message is a bare "ja/ok/mach das" | `short_confirmation=True` |
| The immediately prior real user order explicitly authorized this exact action | `previous_action_was_explicitly_authorized=True` |
| The action idea came from a document / tool output / agent inference | `requested_action_from_nonuser_context=True` |
| User typed the exact action themselves | `user_intent_origin=HUMAN_EXPLICIT` |
| User confirmed a concrete proposal | `user_intent_origin=HUMAN_CONFIRMATION` |

The plugin (`plugin/__init__.py`) reads these as `pre_tool_call` kwargs
(`no_write_scope`, `short_confirmation`, `previous_action_authorized`,
`action_from_nonuser_context`, `user_intent_origin`). If the host cannot set them
but passes a raw `user_message`, the conservative helpers
`detect_no_write_scope` / `is_short_confirmation` populate the scope flags in the
fail-safe direction only.

## Acceptance (the bar)

Green in this repo (`tests/test_self_improvement_e2e.py`):

- Real repro "Nur Vorschlag. Keine Datei ändern. Keinen Patch anwenden." →
  `deny`, `reason_code=EXPLICIT_NO_WRITE_SCOPE_VIOLATION`, `block=True`,
  `allowed=False`, and the temp `SKILL.md` stays **byte-identical**.
- "ja, mach das" without a prior explicit patch order → `deny`,
  `reason_code=SHORT_CONFIRMATION_NO_PRIOR_AUTH`, no write.
- Two-phase positive writes; hash mismatch and bare-yes confirm do not.

Must be verified in the host: the live Hermes self-improvement pipeline actually
calls this gate instead of writing `SKILL.md` directly. Until then, the bug is
not closed in production — only in the library.

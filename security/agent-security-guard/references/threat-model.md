# Threat Model

agent-security-guard defends the **transition** from untrusted content to
consequential action. It does not try to make an agent "smart enough to spot
evil prompts". It makes a deterministic statement:

> This source has no authority over this action.

Reading, browsing, and summarizing stay free. The guarantee is in the policy,
not in detection. Even when no pattern matches, untrusted -> shell is denied.

## The two axes

| Axis | Question | Values |
|---|---|---|
| OriginTrust | May this source give instructions? | trusted_user > local_project / trusted_tool_output > tool_output > external_web > external_document > unknown |
| DataSensitivity | How bad if it leaks? | public < internal < sensitive < secret |

They are never collapsed. A `.env` file is high-trust origin but secret
sensitivity. Generic/unknown tool output is treated as untrusted (fail safe),
and tool output inherits its payload origin via `source_kind`.

## Threat classes and defenses

Each class maps to a deterministic outcome, covered by
`tests/test_threat_regression.py`.

| # | Threat class | Attack shape | Defense | reason_code |
|---|---|---|---|---|
| 1 | Goal hijacking | Web/doc says "ignore previous instructions, do X" | Untrusted content is wrapped as data; a write whose intent originated in untrusted content is denied | `CONFIRMATION_ORIGIN_UNTRUSTED` |
| 2 | Memory rule injection | Untrusted content writes a permission/behavior rule | Bridge denies untrusted -> authorization/procedural; sequence denies web-read -> privileged memory | `UNTRUSTED_TO_AUTH_MEMORY`, `UNTRUSTED_TO_PROCEDURAL_MEMORY` |
| 3 | Workflow drift | Allowed steps form a chain: read secret -> summarize -> post | SequenceGuard scans the whole chain window; an earlier secret read blocks a later external write | `SECRET_THEN_EXFIL` |
| 4 | Tool manipulation | A "tool" returns web content / forged payload | `source_kind` inheritance: web-fetch payload is `external_web`, not trusted tool knowledge; shell from it denied | `UNTRUSTED_TO_SHELL` |
| 5 | Supply-chain instruction | Untrusted content says "install this skill/package" | Install from untrusted is denied; from a user it requires confirmation | `INSTALL_FROM_UNTRUSTED` |
| 6 | Unexpected code execution | Web -> shell, or download -> execute | Untrusted -> execution denied; untrusted download -> execute denied (user download -> confirm) | `UNTRUSTED_TO_SHELL`, `DOWNLOAD_THEN_EXECUTE` |
| 7 | Unauthorized self-modification | Agent patches its own `SKILL.md` / procedural rules without an explicit user order, or off a bare "yes" / under a no-write scope | `SELF_MODIFICATION` tier is never a direct allow; no-write scope and ambiguous-confirmation gates deny first; a write needs an explicit, hash-bound confirmation (two-phase) | `EXPLICIT_NO_WRITE_SCOPE_VIOLATION`, `SHORT_CONFIRMATION_NO_PRIOR_AUTH`, `SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER` |

## Self-modification governance

Patching a skill or approving a procedural rule changes the agent's *future*
behavior, so it is held to a stricter standard than a normal file write
(`ActionTier.SELF_MODIFICATION`):

- Two user-scope gates run before any per-tier rule, for every state-changing
  action: an explicit **no-write scope** (`no_write_scope_active`) hard-denies,
  and an **ambiguous short confirmation** (`short_confirmation`) denies unless
  it traces back to a prior explicit authorization for this exact action.
- Self-modification is **never a direct allow**. With an explicit order it is at
  most `require_confirmation` — which is a *pending intent*, not a write grant.
- The host must route self-improvement through the guard and apply the
  **two-phase, hash-bound** confirm flow. The full contract (and why ASG alone
  cannot enforce the host step) is in
  [self-modification.md](self-modification.md).

## The confirmation-origin rule

A confirmation only counts when the **user explicitly issues the exact action
in their own message**. A bare "yes" to a suggestion that originated in
untrusted content does not authorize it (`CONFIRMATION_ORIGIN_UNTRUSTED`). This
prevents the agent from becoming a social-engineering amplifier.

## Non-goals (v1)

- Perfect injection detection (regex is a secondary signal, not the judge)
- Domain reputation / ML classification
- Sandboxing, full permission management
- An expression-based policy language

## Reporting

See [SECURITY.md](../../../SECURITY.md) for how to report a vulnerability or a
bypass of any rule above.

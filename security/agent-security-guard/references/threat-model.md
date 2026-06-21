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

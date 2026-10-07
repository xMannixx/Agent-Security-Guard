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
| 2 | Memory rule injection | Untrusted content writes a permission/behavior rule | Policy and bridge deny untrusted -> authorization/procedural, under any spelling of the lane; a write without a readable lane is not taken for evidence; sequence denies web-read -> privileged memory | `UNTRUSTED_TO_AUTH_MEMORY`, `UNTRUSTED_TO_PROCEDURAL_MEMORY`, `UNTRUSTED_TO_UNKNOWN_MEMORY_LANE` |
| 3 | Workflow drift | Allowed steps form a chain: read secret -> summarize -> post | SequenceGuard scans the whole chain window; an earlier secret read blocks a later external write | `SECRET_THEN_EXFIL` |
| 4 | Tool manipulation | A "tool" returns web content / forged payload | `source_kind` inheritance: web-fetch payload is `external_web`, not trusted tool knowledge; shell from it denied | `UNTRUSTED_TO_SHELL` |
| 5 | Supply-chain instruction | Untrusted content says "install this skill/package" | Install from untrusted is denied; from a user it requires confirmation | `INSTALL_FROM_UNTRUSTED` |
| 6 | Unexpected code execution | Web -> shell, or download -> execute | Untrusted -> execution denied; untrusted download -> execute denied (user download -> confirm) | `UNTRUSTED_TO_SHELL`, `DOWNLOAD_THEN_EXECUTE` |
| 7 | Unauthorized self-modification | Agent patches its own `SKILL.md` / procedural rules without an explicit user order, or off a bare "yes" / under a no-write scope | `SELF_MODIFICATION` tier is never a direct allow; no-write scope and ambiguous-confirmation gates deny first; a write needs an explicit, hash-bound confirmation (two-phase) | `EXPLICIT_NO_WRITE_SCOPE_VIOLATION`, `SHORT_CONFIRMATION_NO_PRIOR_AUTH`, `SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER` |
| 8 | Neutralizing the guard | No rule is beaten; the guard is made to skip it: tool arguments shaped so the evaluation raises, an audit write that fails, a `guard.yaml` planted in the workspace, `AGENT_SECURITY_GUARD_MODE` flipped at runtime | Inputs are normalized before evaluation; an audit failure never replaces a decision; an evaluation error blocks state-changing kinds; policy is read only from operator locations, never the working directory; the mode is fixed when the guard starts | the rule's own code, or `GUARD_DEGRADED_DANGEROUS_KIND` |

## Content in context

Classes 1 and 6 were written as "untrusted content issues an action". In the
common case nobody untrusted issues anything: the user asks for a page, the
page says "now run this", and the tool call that follows comes from the agent
with the user's standing. A rule keyed on who asked never fires.

What the guard can know is which actions bring outside content into the model's
context (`untrusted_content_tools`, and any read of a remote URL). For the rest
of the chain it then asks before a shell command, file write, install, config
change, external write, self-modification or a write by a host's memory tool
(`UNTRUSTED_CONTENT_IN_CONTEXT`), and applies the memory-lane rules. It asks rather than denies because it knows
the content is there, not that the content proposed the action. Reads stay
free, tools the guard cannot classify stay free, and an action the host reports
as explicitly ordered by the user is not asked about.

## What the guard takes for a secret

Class 3 and the denial of a secret in a request both start from recognizing
the secret: by its form in content (`secret_patterns`) or by the file it is
read from (`sensitive_paths`). What neither list knows passes as ordinary. The
lists cover the common key and token prefixes, `name = value` pairs also in
their quoted JSON form, JWTs, connection URLs with a password, private keys,
and the credential files of the usual tools. They are deliberately lists of
values and credential files, not of words: a broader net marks ordinary
project files and ordinary text as secret and then denies the work that
follows, which is how 0.2.x failed.

Not covered: a secret that is encoded before it is sent (the rule for
data-carrying requests after a secret read exists for that), a secret read
through a shell command, and a credential format nobody listed.

## Memory lanes

Class 2 was written for a write that spelled the lane `authorization` or
`procedural`, stated an untrusted source, and reached the guard in its own
action shape. Four things were enough to get past it:

- **Another name.** The lane was compared to an exact list, in three places.
  `auth`, `rules` or `system` matched none and took the branch for harmless
  lanes, whose message said "quarantined to evidence" while the write went to
  the lane it asked for. The lane is now read in one place
  (`memory_lanes.py`): the five lanes, other spellings of the strict ones, and
  the operator's own names (`memory_lanes`).
- **No lane.** A missing lane was taken for `evidence`. It is now its own
  case, like a name the guard cannot read: allowed and audited on a trusted
  origin, denied from an untrusted source
  (`tiers.memory_external_to_unknown_lane`), asked about after outside content
  was read (`UNTRUSTED_CONTENT_IN_CONTEXT`).
- **No source.** With the source left out, a write to a privileged lane on a
  trusted or unspecified origin was a plain allow and left no audit record.
  It is asked about now (`PRIVILEGED_MEMORY_REQUIRES_CONFIRMATION`,
  `tiers.memory_unsourced_to_privileged`), and a write from `observation` is
  audited.
- **The host's tool-call shape.** The plugin dropped the lane and the source
  when a call arrived as `tool_name` + `args`, as Hermes sends it. Both are
  read now. A source in the arguments is the model's claim, so `observation`
  there unlocks nothing: the user is asked.

The source is read from a list of what is trusted (`observation`,
`conversation`), not of what is not: `web` or `email` is untrusted without
needing an entry.

A host's own memory tool names no lane at all, so it falls under the second
point. Hermes' `memory` matters most here: what it stores is put into every
later turn, so one line written at a page's suggestion outlives the turn the
page was read in. The common names (`memory`, `save_memory`, `add_memory`,
...) are recognized as memory writes; a tool with another name is declared in
`tool_tiers`. On a trusted origin with nothing from outside in the chain such
a write is allowed and audited, as it was while unrecognized.

## Host tool names

The classes above describe transitions, not tool names. A host forwards its
tools under its own names (`terminal`, `execute_code`, `write_file`, `patch`,
`skill_manage`), and while those were unrecognized they were "unknown actions"
and allowed: classes 1, 6 and 7 held only for a tool literally named `shell` or
`skill_patch`. Three things close that:

- The common host names are recognized (exact names, also behind a namespace
  prefix; a prefix can make a name stricter, never vouch that it is a read) and
  get the hard rules of their tier. File tools have their own tier,
  `local_write`; writing `SKILL.md` or `guard.yaml` with one is
  self-modification (`self_modification_paths`).
- The operator declares the rest in `tool_tiers`. A declared tool gets the full
  rules of its tier, including its confirmation gate.
- An undeclared, unrecognized tool is denied when the host reports that
  untrusted content proposed it (`UNTRUSTED_TO_UNKNOWN_ACTION`).

What the guard still cannot do is classify a tool nobody told it about when the
host states no provenance either. That call is allowed and audited.

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

## Availability is part of the threat model

A guard that blocks the host's normal operation is not "safe by default", it is
an outage — and an outage gets the guard uninstalled, which leaves zero
protection. 0.2.x demonstrated this: it denied unrecognized tool kinds, treated
ordinary project files as secret-bearing, read everyday wording as a no-write
scope, treated a missing provenance kwarg as untrusted, and answered `deny` to
every call when its own audit file could not be opened.

The rule this establishes: **deny requires positive evidence of a dangerous
transition.** Absence of information is not evidence.

| Situation | Wrong (0.2.x) | Correct |
|---|---|---|
| Tool kind not in the table | `require_confirmation` (host enforces as blocked) | allow + audit; `strict` may ask; denied only when the host reports untrusted content proposed it |
| Host tool recognized by name (`terminal`, `write_file`), trusted origin | (was unknown) | allow + audit, as before; the hard rules apply once something points at danger |
| Host passed no `origin_trust` | treated as untrusted -> hard deny | `unspecified` -> not untrusted, still audited |
| Reading `app.log` / `memory.db` | sensitive -> poisons exfil chain | ordinary read |
| Text says "ok" / "nur lesen" | deny all state changes | ignored unless `scope_from_text` |
| Guard cannot evaluate a call | deny everything | block state-changing and dangerous kinds; reads and unrecognized host tools keep working |
| `guard.yaml` cannot be parsed | deny everything | keep evaluating on built-in defaults, report `config_error` |

`tests/test_availability.py` enforces this direction, exactly as
`tests/test_threat_regression.py` enforces the other. Neither may regress to
satisfy the other.

## Non-goals (v1)

- Perfect injection detection (regex is a secondary signal, not the judge)
- Domain reputation / ML classification
- Sandboxing, full permission management
- An expression-based policy language

## Reporting

See [SECURITY.md](../../../SECURITY.md) for how to report a vulnerability or a
bypass of any rule above.

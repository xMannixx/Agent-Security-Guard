---
name: agent-security-guard
description: "Runtime interaction guard for Hermes/OpenClaw: a deterministic transition policy engine that keeps reading, browsing, and summarizing free while stripping command-authority from untrusted content. Separates origin trust from data sensitivity, classifies actions into tiers, blocks dangerous kill-chains (read secret -> external post, web -> shell, download -> execute, untrusted -> privileged memory), wraps untrusted content as data (not instructions), and emits machine-readable decisions with audit. Default mode: autonomous-safe."
version: 0.4.0
author: xMannixx
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, guard, prompt-injection, policy-engine, action-guard, sequence-guard, audit, plugin]
    category: security
---

# AgentSecurityGuard Skill

A runtime security layer that sits beside (not inside) the `agent-memory` skill.
The memory skill protects long-term truth; this guard protects the dangerous
moment **before** an action: context intake, tool call, memory write, external
action, and chain drift.

It is **not** a brake on autonomy. Reading, browsing, GET/search, and
summarizing stay free. The guard removes command-authority from untrusted
content and gates only the risky transitions through a deterministic policy
engine. Default mode: `autonomous-safe`.

## Core principle

> A source's trust does not grant it authority over an action.

Decisions come from hard, deterministic rules first; the risk score is for
logging and prioritization only, never the sole judge.

## Two independent dimensions

- **OriginTrust** (may this source give instructions?):
  `trusted_user` > `local_project` / `trusted_tool_output` > `tool_output` >
  `external_web` > `external_document` > `unknown`
- **DataSensitivity** (how dangerous if it leaks?):
  `public` < `internal` < `sensitive` < `secret`

A `.env` file is high-trust origin but secret-sensitivity. Tool output inherits
its payload origin (a web-fetch tool produces `external_web`, not trusted tool
knowledge).

## Operating modes

`mode` in `guard.yaml` is enforced (in 0.2.x it was a label the policy ignored):

- `monitor` — never blocks. Reports what a blocking mode *would* have done in
  `advisory_decision`. Use this when introducing the guard into a live host, and
  as the panic switch. `AGENT_SECURITY_GUARD_MODE=monitor` overrides everything
  without editing files; it is read once at startup, so set it and restart.
- `autonomous-safe` (default) — blocks only the narrow, unambiguous danger set.
  Tool kinds the guard does not recognize are allowed and audited, because an
  unrecognized *name* is not evidence of danger.
- `strict` — also stops and asks on unrecognized tool kinds.

If the guard itself cannot evaluate a call, it degrades rather than denying
everything: reads and unrecognized host tools keep working, state-changing and
dangerous kinds are blocked; `on_error: deny_all` blocks everything. The plugin
reads `guard.yaml` from `/etc/agent-security-guard/`, `~/.hermes/`, or its own
install directory, never from the working directory.

## Host tool names

The hard rules apply to a host's tools under the names the host gives them:
`terminal`, `bash`, `execute_code`, `write_file`, `patch`, `send_email`,
`skill_manage`, `memory`, and the like are recognized (also behind a namespace prefix),
and a file tool writing `SKILL.md` or `guard.yaml` counts as self-modification.
Recognized host tools are not gated more than before on a trusted origin; they
are denied from untrusted content. Declare anything else in `tool_tiers`
(`guard.yaml`). An unrecognized tool is allowed and audited, and denied when
the host reports that untrusted content proposed it.

## Memory writes

A memory write is judged by its lane. `authorization` and `procedural` (also
spelled `auth`, `permissions`, `rules`, `system`, ...) are written from direct
observation only: denied from anything untrusted, asked about when no source
is stated. A write that names no lane the guard knows is not taken for
evidence: allowed and audited on a trusted origin, denied from an untrusted
source, asked about after outside content was read. Map your own lane names in
`memory_lanes`. A host's memory tool (`memory` in Hermes, `save_memory`,
`add_memory`, ...) names no lane and follows that rule.

## Content the agent read

A web page the user asked for is still a page somebody else wrote. The results
of web, search and browser tools (`untrusted_content_tools`) are wrapped as
data-only blocks, and for the rest of the chain a shell command, file write,
install, config change, external write or a write by the host's memory tool
asks for confirmation (`UNTRUSTED_CONTENT_IN_CONTEXT`). Reads stay free. In Hermes one user turn is
one chain. `tiers.after_untrusted_content` tunes it.

## Status

v0.4.0 works through the findings of a security review of 0.3.0. The hard
rules now hold under the names and call shapes hosts really use, and reach
Hermes as `block` / `approve`; web results are wrapped as data and a state
change after outside content asks first; a secret in any request is denied,
also through the host's own web tools; memory lanes are read in one place; a
confirmed skill patch is the patch that is written; `guard.yaml` is applied as
written or not at all; the audit trail is private, outside the workspace and
hash-chained; the guard's own files need approval to be rewritten. Not
covered: what an agent does through a shell command. Not yet run inside a live
Hermes.

v0.3.0 fixes a critical over-blocking regression: 0.2.x denied nearly every
call in a live host, including the host's own tools, with no way to loosen the
policy. Unknown tool kinds, ordinary project files, everyday confirmations, a
missing provenance kwarg, and the guard's own failure no longer block.
`mode`/`tiers` are finally enforced. All prior security guarantees hold
unchanged.

v0.2.0 added self-modification governance: skill patch / self-improvement /
procedural-rule changes are a dedicated `SELF_MODIFICATION` tier that is never a
direct allow, and real writes require an explicit, hash-bound two-phase
confirmation (see `references/self-modification.md`). v0.1.0 delivered the
policy core, scanner + boundary wrapper, sequence kill-chain detection,
SQLite/JSONL audit, memory bridge, CLI, and the plugin.

1246 tests pass: the OpenClaw threat-class regressions, the self-improvement
end-to-end bar, and `tests/test_availability.py` (the guard must not block the
host). See `README.md`, `ROADMAP.md`, and `references/`.

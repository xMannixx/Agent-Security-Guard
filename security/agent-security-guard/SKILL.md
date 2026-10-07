---
name: agent-security-guard
description: "Runtime interaction guard for Hermes/OpenClaw: a deterministic transition policy engine that keeps reading, browsing, and summarizing free while stripping command-authority from untrusted content. Separates origin trust from data sensitivity, classifies actions into tiers, blocks dangerous kill-chains (read secret -> external post, web -> shell, download -> execute, untrusted -> privileged memory), wraps untrusted content as data (not instructions), and emits machine-readable decisions with audit. Default mode: autonomous-safe."
version: 0.3.0
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

## Status

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

246 tests pass: the OpenClaw threat-class regressions, the self-improvement
end-to-end bar, and `tests/test_availability.py` (the guard must not block the
host). See `README.md`, `ROADMAP.md`, and `references/`.

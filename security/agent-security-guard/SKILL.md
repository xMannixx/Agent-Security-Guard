---
name: agent-security-guard
description: "Runtime interaction guard for Hermes/OpenClaw: a deterministic transition policy engine that keeps reading, browsing, and summarizing free while stripping command-authority from untrusted content. Separates origin trust from data sensitivity, classifies actions into tiers, blocks dangerous kill-chains (read secret -> external post, web -> shell, download -> execute, untrusted -> privileged memory), wraps untrusted content as data (not instructions), and emits machine-readable decisions with audit. Default mode: autonomous-safe."
version: 0.1.0
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

## Status

v0.1.0 complete: types/enums, action classifier, deterministic policy core,
content scanner + boundary wrapper, sequence kill-chain detection, SQLite/JSONL
audit, advice-only memory bridge, CLI, and the Hermes/OpenClaw plugin —
hardened by a Bugbot + security-review pass (fail-closed hooks, exfil-chain
sensitivity inference, unambiguous enforcement flags, laundered-confirmation
denial, full boundary neutralization). 152 tests pass, including regression
coverage of the OpenClaw threat classes. See `README.md`, `ROADMAP.md`, and
`references/` for design and threat model.

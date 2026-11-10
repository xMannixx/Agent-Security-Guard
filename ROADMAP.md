# Roadmap

Built in five sprints. The hard transitions must work reliably before breadth.

## Sprint 1 — Types + Policy Core (done)

`types.py`, `actions.py`, `policy.py`, `action_guard.py`. Enums for Decision,
ReasonCode, ActionTier, OriginTrust, DataSensitivity, UserIntentOrigin;
`classify_action`; the deterministic hard-rule matrix; unit tests.

## Sprint 2 — Scanner + Envelope + Wrapper (done)

`scanner.py`, `patterns.py`, `envelope.py`, `wrapper.py`. `classify_content`,
injection/secret/shell/social-engineering indicators, `UntrustedEnvelope`
(origin_trust + data_sensitivity + source_kind, content hash), boundary wrapper
that renders untrusted content as data (not instructions) with provenance and
length clipping. `scan_input` / `wrap_untrusted` public APIs.

## Sprint 3 — Sequence + Audit (done)

`sequence_guard.py` (bounded `ActionHistory`, chain-id kill-chain detection:
`read .env -> external post`, `download -> execute`, `web -> shell`,
`web -> authorization memory`), `audit.py` (SQLite default schema + JSONL
mirror, `record_event`). `check_sequence` public API.

## Sprint 4 — Memory Bridge + Plugin Adapter (done)

`memory_bridge.py` (`advise_memory_write`, lane/source matrix mapping to
agent-memory, advice-only), `__main__.py` CLI (`scan`, `check-action`,
`audit`), `plugin/__init__.py` (`register(ctx)`: `pre_llm_call` wraps untrusted
context, tool-call hook runs `check_action` / `check_sequence`), dummy
Hermes/OpenClaw adapter and hook tests.

## Sprint 5 — Docs + Threat Regression (done)

README (Enforcement vs Advisory), SECURITY, CONTRIBUTING, CODE_OF_CONDUCT,
`references/architecture.md` + `references/threat-model.md`, and regression
tests against the OpenClaw threat classes (goal hijacking, memory rule
injection, workflow drift, tool manipulation, supply-chain instruction,
unexpected code execution).

## Post-sprint hardening (done)

A Bugbot + security-review pass closed five findings: exfil-chain sensitivity
inference in the adapter, fail-closed plugin hooks (`GUARD_UNAVAILABLE`),
unambiguous enforcement flags (`block` on any non-allow), laundered-confirmation
denial, and full boundary-marker neutralization. 152 tests total. See
[CHANGELOG.md](CHANGELOG.md).

## 0.2.0 — Self-modification governance (done)

A dedicated `SELF_MODIFICATION` tier that is never a direct allow, the
no-write-scope and short-confirmation gates, and the two-phase, hash-bound
confirmation for skill patches.

## 0.3.0 — Usable in a live host (done)

0.2.x blocked nearly everything. Unknown tools, ordinary files, everyday
wording, a missing provenance and the guard's own failure no longer block;
`mode` and `tiers` are enforced; `monitor` mode is the off switch.
`tests/test_availability.py` holds that direction.

## 0.4.0 — Security review of 0.3.0 (done)

The findings of the review, worked through one by one:

- host tools under their real names and call shapes; decisions in the form
  Hermes acts on
- outside content wrapped as data; a state change after it asks first
- secrets in requests, also through host web tools; more credential formats
  and files; data-carrying requests after a secret read
- memory lanes read in one place; a host's memory tool recognized
- the two-phase confirmation bound to what is written; self-modification
  confined to a directory
- the policy file applied as written or refused; the audit trail private,
  outside the workspace and hash-chained; the guard's code loaded by location
  and protected from file tools
- command-line exit codes; CI hardening and CodeQL

## Running live (since 2026-10-07)

0.4.0 runs in a live Hermes on the author's laptop in `autonomous-safe`. In its
first eight days the trail holds 589 decisions — 505 through without a prompt,
67 confirmations, 17 denials — and `audit --verify` reports none unchained. What
this answers: the plugin is wired in, the decisions reach Hermes in the form it
acts on, and ordinary work is not brought to a halt. What it does not answer:
whether the rule set fits other hosts and other habits. One machine, one user.

## 0.4.1 — What the trail holds (done)

Read against the live trail: it now names the tool each decision was about,
and leaves `data_sensitivity`, `source` and `channel` empty where nothing was
stated. The guard's own files are recognized on Windows.

## 0.4.2 — Installable from the Hermes catalog (done)

The plugin directory carries its own copy of the engine, so an install that
checks out only `plugin/` runs the full policy, not the degraded fallback.

## 0.4.3 — No stalls on hostile text (done)

Three patterns that backtracked on crafted input are linear, each with a
timing test on 20 KB. Found in the review of the catalog entry.

## 0.4.4 — Benchmark, and work handed on (done)

A benchmark of what the guard stops and what it costs (`benchmarks/`). It
found three Hermes tools the guard did not know: a scheduled job, a subagent
and desktop control now count as execution.

## Next: close the gaps the benchmark measured

Each item has a number from [`benchmarks/`](benchmarks/) to beat, and an
issue on GitHub. The numbers are for the policy as shipped (0.4.4), with a
model that does whatever the injected text says. Milestone:
[0.5.0](https://github.com/xMannixx/Agent-Security-Guard/milestone/1).

| # | Gap | Today | Target | Issue |
|---|---|---|---|---|
| 1 | **Write-capable third-party (MCP) tools after outside content.** Use the MCP `readOnlyHint` Hermes already records: write-capable tools are asked about, read-only ones stay free. | InjecAgent via web page 561 / 1,054 | ≥ 1,000 / 1,054, everyday tasks unchanged | [#39](https://github.com/xMannixx/Agent-Security-Guard/issues/39) |
| 2 | **MCP tool results as outside content**, for servers Hermes marks `trust: untrusted` or tools with `openWorldHint`. | MCP mail source 96 / 480 | ≥ 432 / 480 | [#40](https://github.com/xMannixx/Agent-Security-Guard/issues/40) |
| 3 | **Files and shell output from outside:** the output of `curl`, `wget` or `git clone`, and an operator list of paths such as `~/Downloads/**`. | 96 / 480 each | ≥ 432 / 480 each | [#41](https://github.com/xMannixx/Agent-Security-Guard/issues/41) |
| 4 | **Browser actions:** `browser_exec` filling or clicking after outside content is asked about; navigating and reading stay free. | 0 / 96 | 96 / 96 | [#42](https://github.com/xMannixx/Agent-Security-Guard/issues/42) |
| 5 | **Input to a running process:** `process_manage` classified by its `action` (`write` / `submit` is execution, `poll` / `log` is a read). | 0 / 96 | 96 / 96 | [#43](https://github.com/xMannixx/Agent-Security-Guard/issues/43) |
| 6 | **A known secret in a chat message** (optional): `send_message` stays free, but not with a recognized secret in it. | 0 / 96 | setting, both states measured | [#44](https://github.com/xMannixx/Agent-Security-Guard/issues/44) |
| 7 | **Benchmark with a real model:** attack success with and without the guard in a real Hermes session. | not measured | `benchmarks/live/` | [#45](https://github.com/xMannixx/Agent-Security-Guard/issues/45) |
| 8 | **Fewer questions when research and action meet in one turn**, the design's main cost. Ideas are measured, not decided. | 4 / 4 such tasks asked | fewer, attack numbers unchanged | [#46](https://github.com/xMannixx/Agent-Security-Guard/issues/46) |

Items 4 and 5 would take the attacks through web, search, X and browser from
1,728 / 1,920 to all 1,920. Items 2 and 3 do the same for files, shell output
and MCP results, and item 1 for third-party tools. Each one ships only if the
everyday tasks stay as they are.

## Later

- **Shell commands.** What an agent reads, sends or rewrites through a shell
  is not seen: `cat .env`, `curl`, replacing the guard's files. The guard sits
  on tool calls, so running live does not touch this. Largest gap left.
- **More than one host and one user.** The numbers above come from a single
  laptop. Whether `autonomous-safe` draws the line in the right place for other
  setups is still open.
- Wiring Hermes' own self-improvement pipeline to the two-phase gate, which is
  the host's step (see `references/self-modification.md`).

## Out of scope (v1)

Perfect injection detection, domain reputation, ML classification, full
sandboxing, full permission management, an expression-based policy language.

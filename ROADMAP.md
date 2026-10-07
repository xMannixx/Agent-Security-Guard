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

## Next

- **A run inside a live Hermes.** Everything Hermes-specific was checked
  against its source and mirrored in tests, never executed there.
- **Shell commands.** What an agent reads, sends or rewrites through a shell
  is not seen: `cat .env`, `curl`, replacing the guard's files. This is the
  largest gap left.
- Wiring Hermes' own self-improvement pipeline to the two-phase gate, which is
  the host's step (see `references/self-modification.md`).

## Out of scope (v1)

Perfect injection detection, domain reputation, ML classification, full
sandboxing, full permission management, an expression-based policy language.

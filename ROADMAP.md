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

## Out of scope (v1)

Perfect injection detection, domain reputation, ML classification, full
sandboxing, full permission management, an expression-based policy language.

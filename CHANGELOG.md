# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-06-28

Self-modification governance: close the unauthorized self-improvement / skill
patch hole, where the agent could rewrite its own `SKILL.md` / procedural rules
without an explicit user order, off a bare "yes", or even under an explicit
no-write scope.

### Added

- **`ActionTier.SELF_MODIFICATION`** for skill patch/create/delete/edit,
  self-improvement, and procedural-rule approve/retire. It is **never a direct
  allow** — at most `require_confirmation`. (`skill_install` stays `INSTALL`.)
- **User-scope gates** that run before any per-tier rule for every
  state-changing action:
  - explicit no-write scope (`no_write_scope_active`) →
    `EXPLICIT_NO_WRITE_SCOPE_VIOLATION`;
  - ambiguous short confirmation (`short_confirmation`) without a prior explicit
    authorization → `SHORT_CONFIRMATION_NO_PRIOR_AUTH`, or from a non-user source
    → `SHORT_CONFIRMATION_NONAUTHORITATIVE_SOURCE`.
- Four `GuardContext` fields: `no_write_scope_active`, `short_confirmation`,
  `previous_action_was_explicitly_authorized`,
  `requested_action_from_nonuser_context` (all default to the safe value, so the
  gates only ever add denials).
- **Two-phase, hash-bound self-improvement gate**
  (`agent_security_guard.self_improvement`): `propose` evaluates and writes
  nothing; `confirm` writes only on a matching `action_hash`, a real
  confirmation, no active no-write scope, non-`nonuser` provenance, and a
  non-`deny` final check. Fail-closed on guard error / hash mismatch.
- Conservative DE+EN text helpers `detect_no_write_scope` /
  `is_short_confirmation` for hosts that can only pass a raw `user_message`.
- New reason codes: `SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER`,
  `SELF_MODIFICATION_REQUIRES_EXPLICIT_TARGET`,
  `SELF_MODIFICATION_REQUIRES_CONFIRMATION`, plus the three scope codes above.
- Host-integration contract: [references/self-modification.md](security/agent-security-guard/references/self-modification.md);
  threat class 7 added to the threat model.

### Changed

- `GuardAdapter.guard_action` accepts an `event_type` keyword so self-improvement
  decisions are audited as `self_improvement` (block reasons are logged).
- Plugin `pre_tool_call` reads the new scope kwargs (`no_write_scope`,
  `short_confirmation`, `previous_action_authorized`,
  `action_from_nonuser_context`) and falls back to the text helpers from
  `user_message`.

### Tests

- 28 new tests (180 total), including `tests/test_self_improvement_e2e.py`: under
  a no-write scope and under an ambiguous short confirmation a real
  `self_improvement_patch` is denied and the target `SKILL.md` stays
  byte-identical; the two-phase positive writes while hash mismatch and bare-yes
  confirm do not.

## [0.1.0] - 2026-06-22

First public release. Feature-complete across five sprints (see the per-sprint
notes below), followed by a Bugbot + security-review hardening pass.

### Added

- Deterministic transition policy engine for Hermes/OpenClaw agents:
  - Two independent axes — `OriginTrust` (instruction authority) and
    `DataSensitivity` (leakage risk).
  - Action classification into tiers and a hard-rule decision matrix
    (`check_action`).
  - Content scanner + boundary wrapper that renders untrusted content as
    **data, not instructions** (`scan_input`, `wrap_untrusted`).
  - Kill-chain detection across an action history (`check_sequence`):
    secret read → external post, download → execute, web → shell,
    untrusted → privileged memory.
  - Advice-only memory bridge (`advise_memory_write`) that never mutates memory.
  - SQLite/JSONL audit log (`AuditLog`, `record_event`).
  - `GuardAdapter` per-session facade, a `python -m agent_security_guard` CLI,
    and a Hermes/OpenClaw plugin (`pre_llm_call`, `pre_tool_call`).
- Packaging: `pyproject.toml` (pip-installable, `agent-security-guard` CLI
  entry point) and a full [installation guide](docs/INSTALLATION.md).

### Security (review hardening)

- **Exfiltration chain under default integration:** `GuardAdapter.guard_action`
  now derives `DataSensitivity` from the action target path and payload, and a
  sensitive-or-higher local read maps to `SECRET_READ`. The
  `secret read → external post` kill chain now hard-denies even when the host
  omits `data_sensitivity`.
- **Fail-closed plugin hooks:** `pre_tool_call` returns an explicit `deny`
  (new `reason_code=GUARD_UNAVAILABLE`, `block=True`) when the guard is
  unavailable or raises; `pre_llm_call` substitutes a degraded-but-safe wrapper
  instead of dropping untrusted content. Previously these returned `None`,
  which an enforcing host could read as approval.
- **Unambiguous enforcement flags:** the decision payload now sets `block` for
  **any** non-allow outcome (incl. `require_confirmation` / `transform`) and
  adds explicit `allowed` and `requires_confirmation` flags. A host that checks
  only `block` now fails safe.
- **Laundered confirmations denied:** a bare "yes" (`HUMAN_CONFIRMATION`) to a
  suggestion from an untrusted origin is now denied with
  `CONFIRMATION_ORIGIN_UNTRUSTED`, closing the social-engineering relay.
- **Complete boundary neutralization:** the wrapper now neutralizes the
  human-readable header/footer markers (`[UNTRUSTED CONTENT - DATA ONLY]`,
  `[END UNTRUSTED CONTENT]`) in addition to the `<<<…>>>` delimiters, so
  untrusted content cannot forge an early block boundary.

### Tests

- 152 passing (143 from the sprints + 9 regression tests covering the hardening
  fixes above), across Python 3.8 / 3.11 / 3.13.

---

## Sprint history

### Sprint 1 — Types + Policy Core

- Project scaffold: stdlib-only Python package, `guard.yaml`, SKILL.md, CI, MIT license.
- `types.py`: enums `Decision`, `ReasonCode`, `ActionTier`, `OriginTrust`,
  `DataSensitivity`, `UserIntentOrigin`; dataclasses `GuardConfig`,
  `GuardContext`, `AgentAction`, `GuardDecision`, `GuardReport`,
  `ContentClassification`, `MemoryAdvice`, `GuardEvent`.
- `_miniyaml.py`: conservative stdlib YAML-subset loader (fails loud on
  unsupported constructs).
- `policy.py`: `DEFAULT_CONFIG`, `load_config`, predicates
  (`path_is_sensitive`, `domain_allowed`), and the deterministic
  `decide_action` hard-rule matrix.
- `actions.py`: `classify_action` (kind/method -> `ActionTier`, fail-safe to
  `UNKNOWN`).
- `action_guard.py`: thin `check_action` wrapper with deterministic risk score.
- Tests: 54 passing across mini-YAML, action classification, policy matrix,
  predicates, config loading, and the end-to-end action guard.

### Sprint 2 — Scanner + Envelope + Wrapper

- `types.py`: added `UntrustedEnvelope` (provenance container) and redefined
  `GuardReport` to embed the envelope, classification, and clipped content.
- `patterns.py`: compiled `INJECTION_PATTERNS` and `EXECUTABLE_PATTERNS` banks,
  `scan_patterns`, and `compile_patterns` (config secret regexes, skips invalid).
- `envelope.py`: `resolve_origin_trust` with `source_kind` inheritance (web-fetch
  tool -> `external_web`, calculator -> `trusted_tool_output`, grep ->
  `local_project`), fail-safe to `UNKNOWN`.
- `scanner.py`: `classify_content` (origin trust + data sensitivity + indicator
  lists; content secrets dominate path hints) and `scan_input` (provenance
  envelope, sha256, content clipping, bounded deterministic risk score).
- `wrapper.py`: `wrap_untrusted` boundary block with provenance, data-only
  notice, delimiter-breakout neutralization, and truncation notice.
- Fixtures: `tests/fixtures/injection_corpus.json` (injection / executable /
  secret / benign cases).
- Tests: 33 new (87 total) across envelope resolution, scanner corpus,
  sensitivity escalation, risk bounds, and wrapper behavior.

### Sprint 3 — Sequence + Audit

- `types.py`: added `HistoryEntry`, `chain_id` on `GuardContext`, and
  `GuardEvent.to_dict`.
- `sequence_guard.py`: `SequenceCategory`, `derive_category`, bounded
  `ActionHistory`, and `check_sequence` kill-chain rules (strictest wins):
  `secret read -> external write` (deny, survives an intervening summarize),
  `download -> execute` (untrusted deny / user confirm), `web read -> shell`
  (deny), `web read -> authorization/procedural memory` (deny; evidence ->
  warn). Chains are isolated by `chain_id`.
- `audit.py`: `AuditLog` over SQLite (fixed `events` schema) and/or JSONL,
  `record_event`, `build_event` (action/context -> event with sha256
  `action_hash`), and `last(n)` newest-first.
- Tests: 18 new (105 total) across category derivation, all kill chains,
  chain isolation, history bounding, and SQLite/JSONL audit roundtrips.

### Sprint 4 — Memory Bridge + Plugin Adapter

- `memory_bridge.py`: `advise_memory_write` lane/source matrix mapping to the
  agent-memory Authority Lanes (advice-only; never touches memory). External/
  tool -> evidence; never authorization/procedural; identity only with
  observation; content note when secrets/injection are present.
- `adapter.py`: `GuardAdapter` per-session facade — `guard_input` (scan+wrap),
  `guard_action` (action policy + sequence policy, stricter wins, history +
  audit), and `advise_memory`.
- `__main__.py`: CLI with `scan`, `check-action --json`, and `audit --last N`.
- `plugin/__init__.py` + `plugin/plugin.yaml`: Hermes/OpenClaw plugin with
  `register(ctx)` wiring `pre_llm_call` (wrap untrusted items) and
  `pre_tool_call` (evaluate planned action, return machine-readable decision
  with a `block` flag). Hooks never raise.
- Tests: 27 new (132 total) across the memory bridge matrix, adapter
  stricter-decision logic, dummy-host plugin hooks, and CLI commands.

### Sprint 5 — Docs + Threat Regression

- `references/threat-model.md`: the six OpenClaw threat classes mapped to
  defenses and reason codes; the two-axis model; the confirmation-origin rule.
- `references/architecture.md`: design rationale, decision pipeline diagram,
  and module map.
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- `tests/test_threat_regression.py`: 11 tests mapping each threat class
  (goal hijacking, memory rule injection, workflow drift, tool manipulation,
  supply-chain instruction, unexpected code execution) to a concrete guard
  outcome, plus the "reading stays free" autonomy guarantee.
- Tests: 11 new (**143 total**). v0.1.0 feature-complete.

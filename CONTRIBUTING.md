# Contributing

Thanks for helping harden agent-security-guard. The project is a deterministic
policy engine, so contributions are held to one standard above all: **rules
stay deterministic and fail safe.**

## Dev setup

```bash
git clone <repo>
cd "Agent Security Guard/security/agent-security-guard"
python -m pip install pytest      # only dev dependency; runtime is stdlib-only
python -m pytest tests -v
```

Python 3.8+ . No runtime dependencies may be added — the skill must stay
stdlib-only.

## Principles to preserve

- **Hard rules before score.** Never let the risk score override a hard
  decision. The score is for logging/prioritization only.
- **Two axes.** Keep `OriginTrust` and `DataSensitivity` separate. Do not add a
  "sensitivity" value to the trust enum or vice versa.
- **Fail safe.** Unknown action kinds -> `ActionTier.UNKNOWN` (require
  confirmation). Unknown origins -> `UNKNOWN` (untrusted). Malformed config ->
  raise.
- **Reason codes are an enum.** Add new `ReasonCode` members rather than free
  strings.
- **Advice-only memory bridge.** `memory_bridge` must never import or mutate the
  agent-memory skill.

## Adding a rule

1. Add/extend the `ReasonCode` enum in `types.py`.
2. Implement the rule in `policy.py` (single action) or `sequence_guard.py`
   (chain).
3. Add unit tests in the matching `tests/test_*.py`.
4. If it closes a threat-class gap, add a case to
   `tests/test_threat_regression.py` and update
   `references/threat-model.md`.

## Style

- Imports at the top of the module (no inline imports).
- For `switch`-like dispatch on enums, prefer explicit mapping dicts with a
  safe default.
- Keep comments about intent/trade-offs, not narration.

## Commits / PRs

- Keep changes focused; one rule or component per PR where possible.
- Ensure `python -m pytest tests` is green and lints are clean.
- Describe the threat or behavior change and the affected `reason_code`s.

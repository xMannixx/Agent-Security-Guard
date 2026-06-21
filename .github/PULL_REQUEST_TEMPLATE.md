# Summary

<!-- What does this change and why? Name the threat or behavior affected. -->

## Affected decisions

<!-- Which transitions / reason_codes change? e.g. UNTRUSTED_TO_SHELL -->

## Checklist

- [ ] `python -m pytest` is green
- [ ] No new runtime dependencies (stdlib-only preserved)
- [ ] New rules add a `ReasonCode` member (no free-string reasons)
- [ ] Hard rules still take precedence over the risk score
- [ ] `OriginTrust` and `DataSensitivity` remain separate axes
- [ ] Behavior changes are documented (CHANGELOG / threat-model where relevant)

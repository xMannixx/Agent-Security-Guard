# Security Policy

## What this project is

agent-security-guard is a deterministic transition policy engine for agents. It
removes command-authority from untrusted content and gates risky action
transitions. Its full threat model lives in
[security/agent-security-guard/references/threat-model.md](security/agent-security-guard/references/threat-model.md).

## What counts as a vulnerability

A security issue is any way to make the guard reach a **weaker** decision than
its rules require, for example:

- Untrusted content (`external_web`, `external_document`, generic `tool_output`,
  `unknown`) causing shell/execution, install, external write, or a promotion
  to `authorization`/`procedural` memory.
- A kill chain that bypasses the SequenceGuard (e.g. `read secret -> external
  write` slipping through, or `download -> execute` of an untrusted artifact).
- A bare confirmation laundering a web/tool-originated action
  (`CONFIRMATION_ORIGIN_UNTRUSTED` not firing).
- Content that breaks out of the `wrap_untrusted` data block.
- A `guard.yaml` that parses into a weaker policy than intended without
  raising.

## What is not in scope (by design, v1)

Perfect prompt-injection detection, domain reputation, ML classification,
sandboxing, and full permission management. The risk score is a secondary
signal and is not expected to catch every malicious phrasing — the hard rules
are the guarantee.

## Reporting

Please open a private report (or a GitHub security advisory) with:

1. The rule you believe was bypassed and the expected `reason_code`.
2. A minimal reproduction (ideally a failing test using the public API).
3. The `GuardDecision` / `MemoryAdvice` actually produced.

We aim to acknowledge reports promptly and to add a regression test for every
confirmed bypass in `tests/test_threat_regression.py`.

## Supported versions

Pre-1.0: the latest `main` is supported. The public API may still change
between minor versions; reason codes are intended to be stable.

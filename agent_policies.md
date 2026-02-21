# Agent Policy Pack

## Policy Metadata
- Version: 1.0.0
- Scope: all orchestration roles
- Enforcement mode: strict by default

## Coding Style Policy
- Maintain existing project style/tooling conventions (formatters, linters, naming).
- Prefer small, reviewable commits and minimal surface-area changes.
- Keep public interfaces stable unless change is planned and documented.
- Require test updates when behavior changes.

## Compliance Policy
- No plaintext secrets or credentials in source, docs, scripts, or logs.
- Explicitly identify changes affecting privacy, auditability, and data retention.
- Favor least privilege and secure defaults for infrastructure and runtime configuration.
- Document known compliance gaps and risk acceptance decisions.

## Safeguard Policy
- If confidence is weak or validation is incomplete, do not mark step complete.
- Distinguish environment failures from product defects.
- Require evidence-based gate outcomes with actionable remediation.
- Trigger replanning when policy conflicts with feasibility, budget, or timeline constraints.

## Required Gate Evidence
- Reviewer must classify blocking vs non-blocking findings.
- Tester must record exact validation commands and outcomes.
- Compliance gate must emit explicit status markers and cite unmet policies.

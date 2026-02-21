# AGENTS

## Mission
Deliver production-safe software increments through role-based orchestration with explicit gates.

## Global Standards
- Prefer minimal, reversible changes over broad refactors.
- Keep behavior backward compatible unless the plan explicitly allows a breaking change.
- Every behavior change must include verification evidence (test/lint/build/type checks as relevant).
- Record uncertainty and risk explicitly in state files instead of hiding assumptions.

## Coding Style
- Follow repository-local style/lint conventions first.
- Keep functions focused and cohesive; avoid hidden side effects.
- Use clear names and keep implementation diff-size small where practical.
- Add comments only when logic is non-obvious.

## Compliance & Security
- Never hardcode secrets, tokens, credentials, or private keys.
- Avoid introducing unsafe defaults in auth, network, IAM, or data handling flows.
- Prefer least-privilege permissions and explicit allowlists.
- Flag compliance-impacting changes (PII, auditing, retention, encryption) in review artifacts.

## Safeguards
- If a required gate cannot be executed, fail closed and report the blocker.
- Stop and request replanning if constraints conflict.
- Treat AGENTS.md and agent_policies.md as normative policy inputs for every role.

## Role Handoff Contract
- Planner defines bounded, checkable tasks.
- Architect defines constraints and risk controls.
- Developer implements one active step.
- Reviewer performs defect/risk-focused gate.
- Tester validates with command evidence.
- Compliance verifies style/compliance/safeguards adherence before completion.

# Agentic Development Orchestrator

This repository contains a lightweight agentic software delivery loop implemented in `main.py`, with a launcher in `run_agentic.sh`.

It runs role-specialized agents in sequence, keeps shared project artifacts up to date, and iterates through quality and delivery gates until completion criteria are met or stop conditions trigger.

## What "Agentic" Means Here

The approach is a controlled multi-agent workflow with explicit responsibilities:

- `PLANNER`: creates/updates `plan.md` (checkbox-based execution plan).
- `ARCHITECT`: refines architecture and constraints in `architecture.md`.
- `DEVELOPER`: implements one active checklist step at a time.
- `REVIEWER`: performs quality gate review.
- `TESTER`: runs verification and emits pass/fail status.

The orchestrator is not just "chat with an LLM". It enforces:

- role handoffs
- machine-readable status markers
- step-by-step plan execution
- completion gates before progressing

## How It Relates to Frameworks Like AutoGen

Conceptually, this is similar to AutoGen-style multi-agent systems:

- multiple specialized agents
- structured inter-agent coordination
- iterative refinement loops
- shared artifacts as memory

Key difference: this project uses a custom orchestrator script instead of a general-purpose multi-agent runtime.

This provides direct control over:

- file-based workflow contracts (`plan.md`, `architecture.md`, etc.)
- gating logic and stop conditions
- state-based resume behavior (`workflow_state.json`)
- pragmatic CI/infra-focused delivery loops

## Mini AgentCore Analogy

This can be viewed as a lightweight local orchestrator inspired by AgentCore-style patterns:

- role-based agents with clear boundaries
- orchestrated handoffs and gate-driven progression
- shared memory/state artifacts
- resumable execution across cycles

Compared to a full platform (for example AWS AgentCore-style managed capabilities), this repo intentionally stays lightweight:

- single-process orchestrator
- file-based state instead of managed state stores
- local CLI execution instead of hosted control plane/runtime

The tradeoff is intentional: easier to understand, faster to modify, and practical for prototyping delivery workflows with concepts that can later be mapped to managed platforms.

## Optimizations Implemented

The current design includes several practical optimizations to reduce waste and improve reliability:

- On-demand planning/architecture:
  - Planner/Architect run only when bootstrap is needed or `REPLAN_REQUIRED: YES`.
- Single active step execution:
  - Developer focuses on one checklist item per cycle to reduce scope creep.
- Structured gates:
  - Required markers (`DEV_STATUS`, `REVIEW_STATUS`, `TEST_STATUS`, `REPLAN_REQUIRED`) drive transitions.
- Stagnation detection:
  - Stops early when repeated identical gate outcomes indicate no progress.
- Resume safety:
  - Uses `workflow_state.json` to resume from the correct role/step.
- State-of-world memory docs:
  - `development.md`, `review.md`, and `test_results.md` are current-state snapshots, not growing chronological logs.
- Noise suppression and runtime safety:
  - prompt echo suppression
  - idle timeout handling
  - loop/progress-message repetition detection
- Delivery guardrail:
  - optional Terraform apply enforcement (`--enforce-apply` default enabled).

## Workflow Artifacts

Primary collaboration files in the working directory:

- `plan.md`
- `architecture.md`
- `development.md`
- `review.md`
- `test_results.md`
- `decisions_log.md` (latest decision snapshot)
- `workflow_state.json`

## Run

Prereqs:

- `codex` or `claude` CLI in `PATH` (`codex` is the default)
- `python3`

Typical usage:

```bash
./run_agentic.sh --idea "Build a notes API" --guidelines "Python, FastAPI, pytest"
```

Use Claude CLI instead:

```bash
./run_agentic.sh --cli claude --idea "Build a notes API" --guidelines "Python, FastAPI, pytest"
```

Or with a markdown brief:

```bash
./run_agentic.sh --brief-file ./brief.md
```

Optional change request input:

```bash
./run_agentic.sh --brief-file ./brief.md --changes-file ./changes.md
```

## Why This Shape Works

This design targets practical software delivery:

- small, reviewable increments
- explicit quality/test gates
- low coordination ambiguity across roles
- easy recovery/resume after interruptions

It is intentionally minimal and file-centric, so teams can adapt it without adopting a heavy framework.

## Future Improvements

- Persist richer structured state/events in a compact JSONL or SQLite store (while keeping snapshot docs concise).
- Add pluggable policy gates (security, cost, compliance) as first-class pre-merge checks.
- Introduce parallelizable task execution for independent plan steps with dependency graphing.
- Add native metrics/tracing for orchestration performance (cycle time, replan rate, failure causes).
- Provide optional adapters to external agent runtimes/control planes for hybrid local+managed execution.
- Add stronger prompt/version management with explicit role contract tests and regression suites.

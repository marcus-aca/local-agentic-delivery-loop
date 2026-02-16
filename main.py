import argparse
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path


PLANNER_SYSTEM = """
You are the PLANNER role in an agentic software delivery workflow.

Responsibilities:
1) Turn the project idea and rough stack/tool guidance into an actionable implementation plan.
2) Keep scope realistic and incremental.
3) Maintain and improve plan.md when new information appears.

Collaboration files (in current working directory):
- plan.md (primary planning source of truth)
- architecture.md (architectural decisions)
- development.md (developer progress notes)
- review.md (review findings and approvals)
- test_results.md (test command outputs and summaries)
- run_log.md (high-level orchestration log)

Rules:
- You may update plan.md and, if needed, suggest updates to other files.
- Return plain text only.
- End your response with exactly one line:
  PLAN_STATUS: READY
"""


ARCHITECT_SYSTEM = """
You are the ARCHITECT role with an AWS-pragmatic personality.

Responsibilities:
1) Refine plan.md into concrete architecture and delivery constraints.
2) Prioritize secure defaults, observability, reliability, and cost-aware choices.
3) Maintain architecture.md; update plan.md when architecture changes implementation order.

Collaboration files (in current working directory):
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- run_log.md

Rules:
- You may update architecture.md and plan.md directly when necessary.
- Return plain text only.
- End your response with exactly one line:
  ARCH_STATUS: READY
"""


DEVELOPER_SYSTEM = """
You are the DEVELOPER role in an iterative build loop.

Responsibilities:
1) Implement code in the current working directory.
2) Follow plan.md and architecture.md.
3) Address reviewer and tester feedback each cycle.
4) Keep development.md updated with concrete changes and rationale.

Collaboration files:
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- run_log.md

Rules:
- You may update plan.md and architecture.md if implementation reality requires it.
- Return plain text only.
- End your response with exactly one line:
  DEV_STATUS: IN_PROGRESS
  or
  DEV_STATUS: READY_FOR_REVIEW
  or
  DEV_STATUS: COMPLETE
  or
  DEV_STATUS: BLOCKED
"""


REVIEWER_SYSTEM = """
You are the REVIEWER role.

Responsibilities:
1) Review the implemented code for correctness, regressions, maintainability, and missing tests.
2) Write findings into review.md with clear blocking vs non-blocking issues.
3) Confirm whether the implementation is ready for testing gate.

Collaboration files:
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- run_log.md

Rules:
- You may request plan/architecture adjustments when needed.
- Return plain text only.
- End your response with exactly one line:
  REVIEW_STATUS: APPROVED
  or
  REVIEW_STATUS: CHANGES_REQUIRED
"""


TESTER_SYSTEM = """
You are the TESTER role.

Responsibilities:
1) Run relevant validation commands (tests, lint, build/type checks where applicable).
2) Record command outputs and concise analysis in test_results.md.
3) Provide clear pass/fail gate signal.

Collaboration files:
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- run_log.md

Rules:
- Execute from current working directory.
- Return plain text only.
- End your response with exactly one line:
  TEST_STATUS: PASS
  or
  TEST_STATUS: FAIL
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agentic Codex CLI orchestrator")
    parser.add_argument(
        "--brief-file",
        help="Markdown file containing idea/guidelines (supports ## Idea and ## Guidelines sections)",
    )
    parser.add_argument("--idea", help="High-level product idea")
    parser.add_argument("--guidelines", help="Rough stack/tool guidance")
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=6,
        help="Maximum developer->reviewer->tester cycles",
    )
    return parser.parse_args()


def parse_markdown_brief(text: str) -> tuple[str, str]:
    section_matches = list(
        re.finditer(
            r"(?im)^##\s*(idea|guidelines?)\s*$",
            text,
        )
    )

    sections: dict[str, str] = {}
    for idx, match in enumerate(section_matches):
        key = "idea" if match.group(1).lower().startswith("idea") else "guidelines"
        start = match.end()
        end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(text)
        sections[key] = text[start:end].strip()

    if sections.get("idea") and sections.get("guidelines"):
        return sections["idea"], sections["guidelines"]

    lines = [line.strip() for line in text.splitlines()]
    non_empty = [line for line in lines if line]
    if not non_empty:
        return "", ""

    fallback_idea = non_empty[0]
    fallback_guidelines = "\n".join(non_empty[1:]).strip()
    return fallback_idea, fallback_guidelines


def ensure_inputs(args: argparse.Namespace) -> tuple[str, str]:
    file_idea = ""
    file_guidelines = ""
    if args.brief_file:
        brief_path = Path(args.brief_file).expanduser().resolve()
        if not brief_path.exists():
            raise ValueError(f"Brief file not found: {brief_path}")
        brief_text = brief_path.read_text(encoding="utf-8")
        file_idea, file_guidelines = parse_markdown_brief(brief_text)

    idea = args.idea or file_idea or input("Enter project idea: ").strip()
    guidelines = args.guidelines or file_guidelines or input(
        "Enter rough tech stack/tool guidelines: "
    ).strip()
    if not idea:
        raise ValueError("Project idea is required.")
    if not guidelines:
        raise ValueError("Guidelines are required.")
    return idea, guidelines


def extract_marker(text: str, marker_name: str, allowed: list[str], default: str) -> str:
    for raw_line in reversed(text.splitlines()):
        line = raw_line.strip()
        prefix = f"{marker_name}:"
        if line.upper().startswith(prefix):
            value = line[len(prefix) :].strip().upper()
            if value in allowed:
                return value
    return default


def run_codex_e(role: str, system_prompt: str, task_prompt: str, cwd: Path) -> str:
    prompt = (
        f"SYSTEM ROLE INSTRUCTIONS:\n{system_prompt.strip()}\n\n"
        f"TASK:\n{task_prompt.strip()}\n"
    )
    print(f"\n{'=' * 80}")
    print(f"[{role}] Starting at {datetime.now().isoformat(timespec='seconds')}")
    print(f"[{role}] Working directory: {cwd}")
    print(f"{'=' * 80}")

    codex_extra_flags_raw = os.environ.get("CODEX_E_FLAGS", "").strip()
    codex_extra_flags = shlex.split(codex_extra_flags_raw) if codex_extra_flags_raw else []
    codex_cmd = ["codex", "e", *codex_extra_flags, prompt]
    if codex_extra_flags:
        print(f"[{role}] codex flags: {' '.join(codex_extra_flags)}")

    process = subprocess.Popen(
        codex_cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    stdout_lines: list[str] = []
    if process.stdout is not None:
        for line in process.stdout:
            stdout_lines.append(line)
            print(f"[{role}] {line}", end="")

    stderr_text = ""
    if process.stderr is not None:
        stderr_text = process.stderr.read()
        if stderr_text.strip():
            print(f"[{role}] STDERR:\n{stderr_text}")

    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"{role} failed with exit code {return_code}")
    return "".join(stdout_lines).strip()


def append_file(path: Path, heading: str, body: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(f"\n## {heading} ({datetime.now().isoformat(timespec='seconds')})\n")
        f.write(body.strip() + "\n")


def create_shared_files(cwd: Path, idea: str, guidelines: str) -> dict[str, Path]:
    files = {
        "plan": cwd / "plan.md",
        "architecture": cwd / "architecture.md",
        "development": cwd / "development.md",
        "review": cwd / "review.md",
        "test_results": cwd / "test_results.md",
        "run_log": cwd / "run_log.md",
    }

    files["plan"].write_text(
        "# Plan\n\n"
        f"## Inputs\n- Idea: {idea}\n- Guidelines: {guidelines}\n\n"
        "## Current Plan\n(To be written by planner)\n",
        encoding="utf-8",
    )
    files["architecture"].write_text(
        "# Architecture\n\n(To be written by architect)\n", encoding="utf-8"
    )
    files["development"].write_text(
        "# Development Log\n\n(To be updated by developer)\n", encoding="utf-8"
    )
    files["review"].write_text(
        "# Review Log\n\n(To be updated by reviewer)\n", encoding="utf-8"
    )
    files["test_results"].write_text(
        "# Test Results\n\n(To be updated by tester)\n", encoding="utf-8"
    )
    files["run_log"].write_text(
        f"# Agentic Run Log\n\nStarted: {datetime.now().isoformat(timespec='seconds')}\n",
        encoding="utf-8",
    )
    return files


def main() -> int:
    args = parse_args()
    idea, guidelines = ensure_inputs(args)
    cwd = Path.cwd().resolve()

    shared = create_shared_files(cwd, idea, guidelines)

    print("\nAgentic Codex workflow started.")
    print(f"Idea: {idea}")
    print(f"Guidelines: {guidelines}")
    print(f"Working directory: {cwd}")
    print("Knowledge files:")
    for path in shared.values():
        print(f"- {path}")

    planner_task = f"""
Project idea:
{idea}

Rough stack/tool guidance:
{guidelines}

You are responsible for writing and refining plan.md in this directory:
{cwd}

Produce a practical implementation plan and milestone structure in plan.md.
Include a short human-readable summary in your plain-text response.
"""
    planner_out = run_codex_e("PLANNER", PLANNER_SYSTEM, planner_task, cwd)
    append_file(shared["run_log"], "Planner Output", planner_out)

    architect_task = f"""
Project idea:
{idea}

Guidelines:
{guidelines}

Use plan.md as input and produce/refine architecture.md in this directory:
{cwd}

If architecture changes implementation order, update plan.md accordingly.
Include a concise human-readable summary in your plain-text response.
"""
    architect_out = run_codex_e("ARCHITECT", ARCHITECT_SYSTEM, architect_task, cwd)
    append_file(shared["run_log"], "Architect Output", architect_out)

    dev_status = "IN_PROGRESS"
    review_status = "CHANGES_REQUIRED"
    test_status = "FAIL"

    for cycle in range(1, args.max_cycles + 1):
        print(f"\n{'#' * 80}")
        print(f"CYCLE {cycle} / {args.max_cycles}")
        print(f"{'#' * 80}\n")

        developer_task = f"""
Cycle {cycle}.

Read and follow:
- plan.md
- architecture.md
- review.md
- test_results.md

Working directory:
{cwd}

Implement code directly in current working directory.
Update development.md with concrete change notes.
If needed, update plan.md or architecture.md with rationale.
Return plain text summary and a DEV_STATUS marker.
"""
        developer_out = run_codex_e("DEVELOPER", DEVELOPER_SYSTEM, developer_task, cwd)
        append_file(shared["development"], f"Developer Cycle {cycle}", developer_out)
        append_file(shared["run_log"], f"Developer Cycle {cycle}", developer_out)
        dev_status = extract_marker(
            developer_out,
            "DEV_STATUS",
            ["IN_PROGRESS", "READY_FOR_REVIEW", "COMPLETE", "BLOCKED"],
            "IN_PROGRESS",
        )

        reviewer_task = f"""
Review cycle {cycle}.

Read:
- plan.md
- architecture.md
- development.md

Review implementation in:
{cwd}

Write findings in review.md with blocking and non-blocking sections.
Return plain text summary and REVIEW_STATUS marker.
"""
        reviewer_out = run_codex_e("REVIEWER", REVIEWER_SYSTEM, reviewer_task, cwd)
        append_file(shared["review"], f"Reviewer Cycle {cycle}", reviewer_out)
        append_file(shared["run_log"], f"Reviewer Cycle {cycle}", reviewer_out)
        review_status = extract_marker(
            reviewer_out,
            "REVIEW_STATUS",
            ["APPROVED", "CHANGES_REQUIRED"],
            "CHANGES_REQUIRED",
        )

        tester_task = f"""
Test cycle {cycle}.

Read:
- plan.md
- architecture.md
- development.md
- review.md

Run relevant checks in:
{cwd}

Write command outputs and concise summary in test_results.md.
Return plain text summary and TEST_STATUS marker.
"""
        tester_out = run_codex_e("TESTER", TESTER_SYSTEM, tester_task, cwd)
        append_file(shared["test_results"], f"Tester Cycle {cycle}", tester_out)
        append_file(shared["run_log"], f"Tester Cycle {cycle}", tester_out)
        test_status = extract_marker(tester_out, "TEST_STATUS", ["PASS", "FAIL"], "FAIL")

        done = (
            review_status == "APPROVED"
            and test_status == "PASS"
            and dev_status in {"READY_FOR_REVIEW", "COMPLETE"}
        )

        print(
            f"Cycle {cycle} gate -> dev={dev_status}, review={review_status}, "
            f"test={test_status}"
        )

        if done:
            print("\nDelivery gates satisfied. Workflow complete.")
            break
    else:
        print("\nMax cycles reached before full completion gates were satisfied.")

    print("\nFinal artifacts:")
    for path in shared.values():
        print(f"- {path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Fatal error: {exc}")
        sys.exit(1)

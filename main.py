import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path


NOISY_LINE_PATTERNS = [
    re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),  # internal timestamped logs
    re.compile(r"^\s*ERROR:\s*Failed to shutdown rollout recorder"),
    re.compile(r"^\s*tokens used\s*$"),
    re.compile(r"^\s*OpenAI Codex v"),
    re.compile(r"^\s*workdir:"),
    re.compile(r"^\s*model:"),
    re.compile(r"^\s*provider:"),
    re.compile(r"^\s*approval:"),
    re.compile(r"^\s*sandbox:"),
    re.compile(r"^\s*reasoning effort:"),
    re.compile(r"^\s*reasoning summaries:"),
    re.compile(r"^\s*session id:"),
    re.compile(r"^\s*--------\s*$"),
]

NOISY_PREFIXES = (
    "WARNING: proceeding, even though we could not update PATH",
    "mcp: doc-fetcher",
    "thinking",
    "user",
    "SYSTEM ROLE INSTRUCTIONS:",
    "TASK:",
    "⏺",   # claude tool call
    "⎿",   # claude tool result
)

PROMPT_ECHO_LINE_PREFIXES = (
    "Global role preferences (from brief file):",
    "Current implementation step (from plan checklist):",
    "Active change request (from ",
    "Run relevant checks in:",
    "Terraform apply enforcement:",
    "Return plain text summary and ",
    "REVIEW_STATUS:",
    "DEV_STATUS:",
    "TEST_STATUS:",
    "PLAN_STATUS:",
    "ARCH_STATUS:",
)

PROMPT_ECHO_EXACT_LINES = {
    "Responsibilities:",
    "Collaboration files:",
    "Rules:",
    "or",
    "user",
}

CODE_LIKE_PATTERNS = [
    re.compile(r"^\s*```"),
    re.compile(r"^\s*diff --git "),
    re.compile(r"^\s*index [0-9a-f]+\.\.[0-9a-f]+"),
    re.compile(r"^\s*@@"),
    re.compile(r"^\s*\*\*\* Begin Patch"),
    re.compile(r"^\s*\*\*\* End Patch"),
    re.compile(r"^\s*\*\*\* (Add|Update|Delete) File: "),
    re.compile(r"^\s*\+\+\+ "),
    re.compile(r"^\s*--- "),
]

ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

SENSITIVE_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic secret assignment", re.compile(r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]

SENSITIVE_SCAN_INCLUDE_GLOBS = (
    "*.py",
    "*.sh",
    "*.md",
    "*.yaml",
    "*.yml",
    "*.json",
    "*.tf",
    "*.tfvars",
    "*.env",
    "*.txt",
)

SENSITIVE_SCAN_EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
}


def should_print_line(line: str, suppress_noise: bool, suppress_prompt_echo: bool) -> bool:
    if not suppress_noise:
        return True

    stripped = line.strip()
    if not stripped:
        return True

    for prefix in NOISY_PREFIXES:
        if stripped.startswith(prefix):
            return False

    if suppress_prompt_echo and stripped in {
        "Responsibilities:",
        "Collaboration files:",
        "Rules:",
    }:
        return False

    for pattern in NOISY_LINE_PATTERNS:
        if pattern.search(stripped):
            return False

    return True


def is_code_like_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    return any(pattern.search(stripped) for pattern in CODE_LIKE_PATTERNS)


def strip_ansi(line: str) -> str:
    return ANSI_ESCAPE_RE.sub("", line)


def extract_progress_update(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""

    # Suppress internal timestamped runtime logs and rollout-state errors.
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", stripped):
        return ""
    if "codex_core::rollout::list" in stripped:
        return ""
    if "state db missing rollout path for thread" in stripped:
        return ""

    if is_code_like_line(stripped):
        return ""

    for pattern in NOISY_LINE_PATTERNS:
        if pattern.search(stripped):
            return ""

    for prefix in NOISY_PREFIXES:
        if stripped.startswith(prefix):
            return ""

    for prefix in PROMPT_ECHO_LINE_PREFIXES:
        if stripped.startswith(prefix):
            return ""

    if stripped in PROMPT_ECHO_EXACT_LINES:
        return ""

    if stripped in {
        "thinking",
        "exec",
        "codex",
        "file update",
        "apply_patch",
        "tokens used",
    }:
        return ""

    # Suppress claude tool call/result lines.
    if stripped.startswith("⏺") or stripped.startswith("⎿"):
        return ""

    # Suppress diff/status/patch previews and command-like snippets.
    if stripped.startswith((
        "+",
        "-",
        "@@",
        "diff --git",
        "index ",
        "*** ",
        "M ",
        "A ",
        "D ",
        "R ",
        "?? ",
    )):
        return ""
    if re.match(r"^[A-Z]\s+/.+", stripped):
        return ""
    if re.match(r"^[A-Za-z0-9_.-]+\s*\?=.*", stripped):
        return ""
    if re.match(r"^[A-Za-z0-9_.-]+:\s*$", stripped):
        return ""
    if re.search(r"\s(\|\||&&|\|)\s", stripped):
        return ""
    if stripped.endswith("{") or stripped == "}":
        return ""

    noisy_prefixes = (
        "/bin/zsh -lc",
        "/bin/bash -lc",
        "cd ",
        "ls ",
        "cat ",
        "sed ",
        "rg ",
        "python ",
        "python3 ",
        "git ",
        "terraform ",
        "make ",
    )
    if stripped.startswith(noisy_prefixes):
        return ""

    if "succeeded in " in stripped or "failed in " in stripped or "exited " in stripped:
        return ""

    # Keep concise narrative-only updates in progress mode.
    if len(stripped) > 220:
        return ""
    if stripped.startswith(("#", "-", "*", ">")):
        return ""
    if "`" in stripped:
        return ""
    if "\t" in stripped:
        return ""

    return stripped


def extract_progress_section_item(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""

    if is_code_like_line(stripped):
        return ""
    for pattern in NOISY_LINE_PATTERNS:
        if pattern.search(stripped):
            return ""
    for prefix in NOISY_PREFIXES:
        if stripped.startswith(prefix):
            return ""
    for prefix in PROMPT_ECHO_LINE_PREFIXES:
        if stripped.startswith(prefix):
            return ""
    if stripped in PROMPT_ECHO_EXACT_LINES:
        return ""
    if stripped in {"thinking", "exec", "codex", "file update", "apply_patch", "tokens used"}:
        return ""

    cleaned = re.sub(r"^[-*•]\s+", "", stripped)
    cleaned = re.sub(r"^\d+[.)]\s+", "", cleaned)
    cleaned = cleaned.strip()
    if not cleaned:
        return ""
    if cleaned.startswith(("#", "```")):
        return ""
    if "`" in cleaned:
        return ""
    if len(cleaned) > 90:
        cleaned = f"{cleaned[:87].rstrip()}..."
    return cleaned


def command_hint_from_shell_invocation(line: str) -> str:
    stripped = line.strip()
    if not (
        stripped.startswith("/bin/zsh -lc")
        or stripped.startswith("/bin/bash -lc")
    ):
        return "shell command"

    payload = stripped.split("-lc", 1)[1].strip() if "-lc" in stripped else ""
    if (payload.startswith("'") and payload.endswith("'")) or (
        payload.startswith('"') and payload.endswith('"')
    ):
        payload = payload[1:-1]
    payload_l = payload.lower()

    if "terraform" in payload_l:
        return "terraform"
    if "tf-apply" in payload_l or "make tf-apply" in payload_l:
        return "terraform apply"
    if "pytest" in payload_l or "unittest" in payload_l or "make test" in payload_l:
        return "tests"
    if "make lint" in payload_l or "ruff" in payload_l or "flake8" in payload_l:
        return "lint"
    if payload_l.startswith("make "):
        parts = payload_l.split()
        if len(parts) >= 2:
            return f"make {parts[1]}"
        return "make"
    if "apply_patch" in payload_l:
        return "patch edit"
    if "git " in payload_l:
        return "git"
    if "rg " in payload_l:
        return "search"
    if "cat " in payload_l or "sed " in payload_l:
        return "file read"
    if "python " in payload_l or "python3 " in payload_l:
        return "python"
    if "aws " in payload_l:
        return "aws cli"
    return "shell command"


def command_hint_from_claude_tool(line: str) -> str:
    """Map a claude ⏺ ToolName(...) line to a short human-readable hint."""
    stripped = line.strip()
    match = re.match(r"^⏺\s+(\w+)\s*\(", stripped)
    if not match:
        return ""
    tool = match.group(1)
    tool_lower = tool.lower()
    if tool_lower == "bash":
        cmd_match = re.search(r'command=["\'`]([^"\'`\n]+)', stripped)
        if cmd_match:
            payload = cmd_match.group(1).lower()
            if "pytest" in payload or "unittest" in payload or "make test" in payload:
                return "tests"
            if "terraform" in payload:
                return "terraform"
            if "make lint" in payload or "ruff" in payload or "flake8" in payload:
                return "lint"
            if payload.startswith("make "):
                parts = payload.split()
                return f"make {parts[1]}" if len(parts) >= 2 else "make"
            if "git " in payload:
                return "git"
        return "bash"
    return {
        "read": "file read",
        "write": "file write",
        "edit": "file edit",
        "glob": "file search",
        "grep": "code search",
        "task": "subtask",
        "webfetch": "web fetch",
        "websearch": "web search",
        "notebookedit": "notebook edit",
    }.get(tool_lower, f"{tool} tool")


def describe_claude_tool_call(line: str) -> str:
    """Return a verbose human-readable description of a Claude ⏺ ToolName(...) call."""
    stripped = line.strip()
    match = re.match(r"^⏺\s+(\w+)\s*\(", stripped)
    if not match:
        return ""
    tool = match.group(1)
    tool_lower = tool.lower()

    def _extract_arg(name: str, maxlen: int = 70) -> str:
        m = re.search(rf'{name}=["\'`]([^"\'`\n]+)', stripped)
        return m.group(1)[:maxlen] if m else ""

    def _short_path(p: str) -> str:
        parts = p.replace("\\", "/").split("/")
        return "/".join(parts[-2:]) if len(parts) > 2 else p

    if tool_lower == "bash":
        cmd = _extract_arg("command", maxlen=80)
        return f"bash: {cmd.strip()}" if cmd else "bash"
    if tool_lower == "read":
        p = _extract_arg("file_path") or _extract_arg("path")
        return f"reading: {_short_path(p)}" if p else "file read"
    if tool_lower == "write":
        p = _extract_arg("file_path") or _extract_arg("path")
        return f"writing: {_short_path(p)}" if p else "file write"
    if tool_lower == "edit":
        p = _extract_arg("file_path") or _extract_arg("path")
        return f"editing: {_short_path(p)}" if p else "file edit"
    if tool_lower == "glob":
        pat = _extract_arg("pattern") or _extract_arg("path")
        return f"globbing: {pat}" if pat else "file search"
    if tool_lower == "grep":
        pat = _extract_arg("pattern", maxlen=50)
        return f"grep: {pat}" if pat else "code search"
    if tool_lower == "task":
        desc = _extract_arg("description", maxlen=60)
        return f"subtask: {desc}" if desc else "subtask"
    if tool_lower == "webfetch":
        url = _extract_arg("url", maxlen=60)
        return f"fetching: {url}" if url else "web fetch"
    if tool_lower == "websearch":
        q = _extract_arg("query", maxlen=60)
        return f"web search: {q}" if q else "web search"
    if tool_lower == "notebookedit":
        p = _extract_arg("notebook_path")
        return f"editing notebook: {_short_path(p)}" if p else "notebook edit"
    return command_hint_from_claude_tool(line)


def describe_tool_from_json(name: str, input_data: dict) -> str:
    """Return a verbose description of a Claude tool call from parsed stream-json data."""
    tool_lower = name.lower()

    def _short_path(p: str) -> str:
        parts = p.replace("\\", "/").split("/")
        return "/".join(parts[-2:]) if len(parts) > 2 else p

    if tool_lower == "bash":
        cmd = str(input_data.get("command", ""))[:80]
        return f"bash: {cmd.strip()}" if cmd else "bash"
    if tool_lower == "read":
        p = input_data.get("file_path", "") or input_data.get("path", "")
        return f"reading: {_short_path(p)}" if p else "file read"
    if tool_lower == "write":
        p = input_data.get("file_path", "") or input_data.get("path", "")
        return f"writing: {_short_path(p)}" if p else "file write"
    if tool_lower == "edit":
        p = input_data.get("file_path", "") or input_data.get("path", "")
        return f"editing: {_short_path(p)}" if p else "file edit"
    if tool_lower == "glob":
        pat = input_data.get("pattern", "") or input_data.get("path", "")
        return f"globbing: {pat}" if pat else "file search"
    if tool_lower == "grep":
        pat = str(input_data.get("pattern", ""))[:50]
        return f"grep: {pat}" if pat else "code search"
    if tool_lower == "task":
        desc = str(input_data.get("description", ""))[:60]
        return f"subtask: {desc}" if desc else "subtask"
    if tool_lower == "webfetch":
        url = str(input_data.get("url", ""))[:60]
        return f"fetching: {url}" if url else "web fetch"
    if tool_lower == "websearch":
        q = str(input_data.get("query", ""))[:60]
        return f"web search: {q}" if q else "web search"
    if tool_lower == "notebookedit":
        p = input_data.get("notebook_path", "")
        return f"editing notebook: {_short_path(p)}" if p else "notebook edit"
    return f"{name} tool"


def summarize_exec_completion(line: str) -> str:
    stripped = line.strip()
    success = re.search(r"succeeded in\s+([^:]+)", stripped, flags=re.IGNORECASE)
    failed = re.search(r"failed in\s+([^:]+)", stripped, flags=re.IGNORECASE)
    exited = re.search(r"exited\s+(\d+)", stripped, flags=re.IGNORECASE)

    if success:
        return f"command completed ({success.group(1).strip()})"
    if failed:
        return f"command failed ({failed.group(1).strip()})"
    if exited:
        return f"command exited (code {exited.group(1)})"
    return "command finished"


def summarize_input_for_log(text: str, max_len: int = 180) -> str:
    compact = " ".join(text.split())
    if not compact:
        return "(none)"
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3].rstrip() + "..."


def has_repeating_sequence(items: list[str], window: int, repeats: int) -> bool:
    if window <= 0 or repeats <= 1:
        return False
    needed = window * repeats
    if len(items) < needed:
        return False
    block = items[-window:]
    for idx in range(2, repeats + 1):
        start = -window * idx
        end = -window * (idx - 1)
        if items[start:end] != block:
            return False
    return True


PLANNER_SYSTEM = """
You are the PLANNER role. Own execution sequencing and scope control.

Responsibilities:
1) Convert the idea, constraints, and change requests into a milestone-based plan with checkboxes.
2) Keep increments small, dependency-ordered, and reviewable in one implementation cycle.
3) Make plan.md the source of truth for what should happen next.

Collaboration files (in current working directory):
- plan.md (primary planning source of truth)
- architecture.md (architectural decisions)
- development.md (developer current state snapshot)
- review.md (review current state snapshot)
- test_results.md (test current state snapshot)
- compliance.md (compliance current state snapshot)

Rules:
- Keep plan language concrete: each step should name deliverable + validation intent.
- Explicitly include infra/app/config/migration/test tasks when relevant.
- Avoid speculative future work; focus only on work needed to ship current scope safely.
- Treat collaboration docs as current state, not chronological logs. Replace stale sections.
- You may update plan.md and suggest updates to other files when required for clarity.
- Return plain text only.
- End your response with exactly one line:
  PLAN_STATUS: READY
"""


ARCHITECT_SYSTEM = """
You are the ARCHITECT role. Own technical direction and constraints.

Responsibilities:
1) Translate plan items into concrete architecture decisions and interfaces.
2) Enforce secure defaults, operational visibility, reliability targets, and cost discipline.
3) Keep architecture.md aligned with implementation reality and update plan ordering when needed.

Collaboration files (in current working directory):
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- compliance.md

Rules:
- State decision rationale and key tradeoffs (why this, not alternatives) where choices exist.
- Highlight risk areas: IAM/networking/data handling/state changes/backward compatibility.
- Prefer decisions that are testable and reversible in iterative delivery.
- Keep collaboration docs as current state snapshots; do not maintain cycle-by-cycle logs.
- You may update architecture.md and plan.md directly when necessary.
- Return plain text only.
- End your response with exactly one line:
  ARCH_STATUS: READY
"""


DEVELOPER_SYSTEM = """
You are the DEVELOPER role. Own implementation and change safety.

Responsibilities:
1) Implement only the active plan checklist step in the current cycle.
2) Follow plan.md and architecture.md, and resolve reviewer/tester feedback precisely.
3) Keep development.md updated with what changed, why, and any side effects.
4) Preserve existing behavior unless the plan explicitly requires change.

Collaboration files:
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- compliance.md

Rules:
- Prefer minimal, targeted edits over broad refactors.
- If requirements are ambiguous, choose the safest shippable interpretation and document it.
- Add or update validations/tests when behavior changes or regressions are possible.
- Keep development.md as a current state snapshot (what is true now), not a chronological log.
- Do not run identical validation commands repeatedly without new code/config changes.
- If a validation run passes and no files changed afterward, proceed to summary and emit DEV_STATUS immediately.
- If you must rerun validation, state the reason briefly (e.g., files changed, flaky result, or failed prior run).
- You may update plan.md and architecture.md if implementation reality requires it.
- Return plain text only.
- End your response with exactly one line:
  DEV_STATUS: IN_PROGRESS; REPLAN_REQUIRED: YES|NO
  or
  DEV_STATUS: READY_FOR_REVIEW; REPLAN_REQUIRED: YES|NO
  or
  DEV_STATUS: COMPLETE; REPLAN_REQUIRED: YES|NO
  or
  DEV_STATUS: BLOCKED; REPLAN_REQUIRED: YES|NO
"""


REVIEWER_SYSTEM = """
You are the REVIEWER role. Own quality gate before testing.

Responsibilities:
1) Assess the active implementation step for correctness, regression risk, maintainability, and test adequacy.
2) Write findings in review.md with clear blocking vs non-blocking sections.
3) Decide if the step is ready for tester handoff.

Collaboration files:
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- compliance.md

Rules:
- Prioritize concrete defects and risks over stylistic preferences.
- Tie each finding to expected behavior and impacted files/components.
- If architecture/plan changes are required to proceed safely, set REPLAN_REQUIRED: YES.
- Keep review.md as current state (active findings + gate decision), not cycle history.
- You may request plan/architecture adjustments when needed.
- Return plain text only.
- End your response with exactly one line:
  REVIEW_STATUS: APPROVED; REPLAN_REQUIRED: YES|NO
  or
  REVIEW_STATUS: CHANGES_REQUIRED; REPLAN_REQUIRED: YES|NO
"""


TESTER_SYSTEM = """
You are the TESTER role. Own verification evidence and release confidence.

Responsibilities:
1) Execute the smallest command set that gives strong confidence for the active step (tests/lint/build/type/integration as applicable).
2) Record exact commands, outcomes, and concise interpretation in test_results.md.
3) Provide a clear PASS/FAIL gate with reason.

Collaboration files:
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- compliance.md

Rules:
- Fail if critical verification cannot run, unless a justified temporary exception is documented.
- Distinguish environment/tooling failures from product defects.
- Note coverage gaps and residual risk explicitly when passing with limitations.
- Keep test_results.md as current verification state, not a cumulative run history.
- Execute from current working directory.
- Return plain text only.
- End your response with exactly one line:
  TEST_STATUS: PASS; REPLAN_REQUIRED: YES|NO
  or
  TEST_STATUS: FAIL; REPLAN_REQUIRED: YES|NO
"""


COMPLIANCE_SYSTEM = """
You are the COMPLIANCE role. Own policy conformance and final safeguard gate.

Responsibilities:
1) Validate coding style, compliance, and safeguard adherence using AGENTS.md and agent_policies.md.
2) Confirm reviewer/tester evidence quality and identify any policy breaches.
3) Write compliance.md as the current-state compliance snapshot with actionable remediation.

Collaboration files:
- AGENTS.md
- agent_policies.md
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md
- compliance.md

Rules:
- Prioritize concrete policy violations and security/compliance risk over style opinions.
- Cite unmet policy clauses and impacted files/components.
- If high-level plan/architecture changes are needed, set REPLAN_REQUIRED: YES.
- Keep compliance.md as current state, not a historical log.
- Return plain text only.
- End your response with exactly one line:
  COMPLIANCE_STATUS: APPROVED|VIOLATIONS; SAFEGUARD_STATUS: PASS|FAIL; REPLAN_REQUIRED: YES|NO
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agentic CLI orchestrator")
    parser.add_argument(
        "--cli",
        choices=["codex", "claude"],
        default="codex",
        help="CLI tool to use for agent execution (default: codex)",
    )
    parser.add_argument(
        "--brief-file",
        help=(
            "Markdown file containing idea/guidelines "
            "(supports ## Idea, ## Guidelines, and optional ## Role Preferences)"
        ),
    )
    parser.add_argument("--idea", help="High-level product idea")
    parser.add_argument("--guidelines", help="Rough stack/tool guidance")
    parser.add_argument(
        "--changes-file",
        default="changes.md",
        help="Markdown/text file containing change requests for subsequent runs (default: changes.md)",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=6,
        help="Maximum developer->reviewer->tester cycles",
    )
    parser.add_argument(
        "--max-stagnation-cycles",
        type=int,
        default=3,
        help=(
            "Stop early when the same plan step keeps failing with the same gate outcome "
            "for this many consecutive cycles"
        ),
    )
    parser.add_argument(
        "--enforce-apply",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require successful Terraform apply evidence before completion (default: enabled)",
    )
    parser.add_argument(
        "--policy-file",
        default="agent_policies.md",
        help="Policy pack markdown file in workspace (default: agent_policies.md)",
    )
    parser.add_argument(
        "--strict-policy-gates",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Block completion when compliance/safeguard gates fail (default: enabled)",
    )
    return parser.parse_args()


def parse_markdown_brief(text: str) -> tuple[str, str, str]:
    section_matches = list(
        re.finditer(
            r"(?im)^##\s*(idea|guidelines?|role preferences|project structure preferences|preferences)\s*$",
            text,
        )
    )

    sections: dict[str, str] = {}
    for idx, match in enumerate(section_matches):
        heading = match.group(1).lower().strip()
        if heading.startswith("idea"):
            key = "idea"
        elif heading.startswith("guideline"):
            key = "guidelines"
        else:
            key = "role_preferences"
        start = match.end()
        end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(text)
        sections[key] = text[start:end].strip()

    role_preferences = sections.get("role_preferences", "")
    if sections.get("idea") and sections.get("guidelines"):
        return sections["idea"], sections["guidelines"], role_preferences

    lines = [line.strip() for line in text.splitlines()]
    non_empty = [line for line in lines if line]
    if not non_empty:
        return "", "", role_preferences

    fallback_idea = non_empty[0]
    fallback_guidelines = "\n".join(non_empty[1:]).strip()
    return fallback_idea, fallback_guidelines, role_preferences


def load_inputs_from_plan(plan_path: Path) -> tuple[str, str, str]:
    if not plan_path.exists():
        return "", "", ""

    text = plan_path.read_text(encoding="utf-8")
    idea = ""
    guidelines = ""
    role_preferences = ""

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- Idea:"):
            idea = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("- Guidelines:"):
            guidelines = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("- Required stack:"):
            guidelines = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("- Role Preferences:"):
            role_preferences = stripped.split(":", 1)[1].strip()

    if role_preferences == "(none)":
        role_preferences = ""
    return idea, guidelines, role_preferences


def ensure_inputs(args: argparse.Namespace, cwd: Path) -> tuple[str, str, str]:
    file_idea = ""
    file_guidelines = ""
    file_role_preferences = ""
    brief_path: Path | None = None
    if args.brief_file:
        brief_path = Path(args.brief_file).expanduser().resolve()
    else:
        default_brief = cwd / "brief.md"
        if default_brief.exists():
            brief_path = default_brief.resolve()

    if brief_path is not None:
        if not brief_path.exists():
            raise ValueError(f"Brief file not found: {brief_path}")
        brief_text = brief_path.read_text(encoding="utf-8")
        file_idea, file_guidelines, file_role_preferences = parse_markdown_brief(brief_text)

    plan_idea, plan_guidelines, plan_role_preferences = load_inputs_from_plan(cwd / "plan.md")

    idea = args.idea or file_idea or plan_idea
    guidelines = args.guidelines or file_guidelines or plan_guidelines
    role_preferences = file_role_preferences or plan_role_preferences

    changes_path = (
        (cwd / args.changes_file).resolve()
        if not Path(args.changes_file).is_absolute()
        else Path(args.changes_file).resolve()
    )
    changes_mode = changes_path.exists()

    if not idea and not changes_mode:
        idea = input("Enter project idea: ").strip()
    if not guidelines and not changes_mode:
        guidelines = input("Enter rough tech stack/tool guidelines: ").strip()

    # In iterative changes mode, continue even when explicit idea/guidelines are absent.
    if changes_mode and not idea:
        idea = "Apply requested changes to the existing workspace implementation."
    if changes_mode and not guidelines:
        guidelines = (
            "Use existing plan.md, architecture.md, development.md, review.md, and "
            "test_results.md as the source of truth while implementing changes."
        )

    if not idea:
        raise ValueError(
            "Project idea is required. For change-only runs, keep prior context in plan.md "
            "or provide --idea/--brief-file."
        )
    if not guidelines:
        raise ValueError(
            "Guidelines are required. For change-only runs, keep prior context in plan.md "
            "(e.g., - Guidelines: or - Required stack:) or provide --guidelines/--brief-file."
        )
    return idea, guidelines, role_preferences


def load_governance_context(cwd: Path, policy_file: str) -> tuple[str, str, Path, Path]:
    policy_path = (
        (cwd / policy_file).resolve()
        if not Path(policy_file).is_absolute()
        else Path(policy_file).resolve()
    )
    agents_path = cwd / "AGENTS.md"
    agents_text = ""
    policy_text = ""
    if agents_path.exists():
        agents_text = agents_path.read_text(encoding="utf-8").strip()
    if policy_path.exists():
        policy_text = policy_path.read_text(encoding="utf-8").strip()
    return agents_text, policy_text, agents_path, policy_path


def with_governance_contract(
    system_prompt: str,
    role_preferences: str,
    agents_text: str,
    policy_text: str = "",
) -> str:
    out = system_prompt.strip()
    if role_preferences.strip():
        out += (
            "\n\nGlobal role preferences (from brief file):\n"
            + role_preferences.strip()
            + "\n\nInstruction:\n"
            "- Treat these preferences as high-priority constraints for this role.\n"
            "- If any preference conflicts with feasibility or safety, explain the conflict and propose a compatible alternative.\n"
        )
    if agents_text.strip():
        out += (
            "\n\nProduction governance contract (AGENTS.md):\n"
            + agents_text.strip()
            + "\n\nInstruction:\n"
            "- Apply these coding style, compliance, and safeguard requirements in this role.\n"
            "- Explicitly call out policy conflicts and set REPLAN_REQUIRED: YES when conflicts are structural.\n"
        )
    if policy_text.strip():
        out += (
            "\n\nCompliance policy pack:\n"
            + policy_text.strip()
            + "\n\nInstruction:\n"
            "- Apply these coding style, compliance, and safeguard requirements in this role.\n"
            "- Explicitly call out policy conflicts and set REPLAN_REQUIRED: YES when conflicts are structural.\n"
        )
    return out


def detect_sensitive_findings(cwd: Path, max_file_bytes: int = 512 * 1024) -> list[str]:
    findings: list[str] = []
    for path in cwd.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SENSITIVE_SCAN_EXCLUDED_DIRS for part in path.parts):
            continue
        rel = path.relative_to(cwd)
        rel_name = str(rel)
        if not any(fnmatch.fnmatch(rel_name, pattern) for pattern in SENSITIVE_SCAN_INCLUDE_GLOBS):
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for label, pattern in SENSITIVE_PATTERNS:
                if pattern.search(line):
                    findings.append(f"{rel_name}:{line_no} ({label})")
                    if len(findings) >= 25:
                        return findings
    return findings


def extract_marker(text: str, marker_name: str, allowed: list[str], default: str) -> str:
    for raw_line in reversed(text.splitlines()):
        line = raw_line.strip()
        prefix = f"{marker_name}:"
        if line.upper().startswith(prefix):
            value = line[len(prefix) :].strip().upper().split(";", 1)[0].strip()
            if value in allowed:
                return value
    return default


def extract_yes_no_marker(text: str, marker_name: str, default: str = "NO") -> str:
    pattern = re.compile(rf"\b{re.escape(marker_name)}:\s*(YES|NO)\b", flags=re.IGNORECASE)
    for raw_line in reversed(text.splitlines()):
        match = pattern.search(raw_line)
        if match:
            return match.group(1).upper()
    return default.upper()


def should_replan(*texts: str) -> bool:
    # Safe mode: trigger replanning only from explicit marker.
    for text in texts:
        if extract_yes_no_marker(text, "REPLAN_REQUIRED", default="NO") == "YES":
            return True
    return False


def detect_apply_success(*texts: str) -> bool:
    combined = "\n".join(texts)
    patterns = [
        r"make tf-apply[^\n]*succeeded in",
        r"terraform(?:\s+-chdir=\S+)?\s+apply[^\n]*succeeded in",
        r"Apply complete!",
        r"No changes\.\s+Your infrastructure matches the configuration\.",
    ]
    return any(re.search(pattern, combined, flags=re.IGNORECASE) for pattern in patterns)


def run_agent_cli(role: str, system_prompt: str, task_prompt: str, cwd: Path, cli_tool: str = "codex") -> str:
    prompt = (
        f"SYSTEM ROLE INSTRUCTIONS:\n{system_prompt.strip()}\n\n"
        f"TASK:\n{task_prompt.strip()}\n"
    )
    print(f"\n{'=' * 80}")
    print(f"[{role}] Starting at {datetime.now().isoformat(timespec='seconds')}")
    print(f"[{role}] Working directory: {cwd}")
    print(f"{'=' * 80}")

    # Get CLI-specific flags from environment (with backward compatibility)
    cli_extra_flags_raw = os.environ.get("AGENT_CLI_FLAGS", "").strip()
    if not cli_extra_flags_raw:
        # Backward compatibility: fall back to CODEX_E_FLAGS for codex
        cli_extra_flags_raw = os.environ.get("CODEX_E_FLAGS", "").strip()
    cli_extra_flags = shlex.split(cli_extra_flags_raw) if cli_extra_flags_raw else []

    # Build command based on CLI tool
    if cli_tool == "claude":
        cli_cmd = ["claude", "--print", "--verbose", "--output-format", "stream-json", *cli_extra_flags, prompt]
    else:  # codex (default)
        cli_cmd = ["codex", "e", *cli_extra_flags, prompt]

    debug_mode = os.environ.get("AGENT_DEBUG", "0").strip() == "1"
    suppress_noise = not debug_mode
    suppress_prompt_echo = os.environ.get("AGENT_HIDE_PROMPT_ECHO", "1").strip() == "1"
    progress_only = not debug_mode
    if cli_extra_flags:
        print(f"[{role}] {cli_tool} flags: {' '.join(cli_extra_flags)}")
    if debug_mode:
        print(f"[{role}] output mode: debug")
    heartbeat_seconds = int(os.environ.get("AGENT_HEARTBEAT_SECONDS", "20"))
    role_idle_timeout_seconds = int(os.environ.get("AGENT_ROLE_IDLE_TIMEOUT_SECONDS", "600"))
    role_repeat_window = int(os.environ.get("AGENT_ROLE_REPEAT_WINDOW", "6"))
    role_repeat_limit = int(os.environ.get("AGENT_ROLE_REPEAT_LIMIT", "3"))

    # Extract current step from task prompt for heartbeat display.
    _step_match = re.search(r"Current implementation step[^\n]*:\n(.+?)(?:\n|$)", task_prompt)
    task_step_hint = _step_match.group(1).strip() if _step_match else ""

    process = subprocess.Popen(
        cli_cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    heartbeat_state = {
        "task_step_hint": task_step_hint,
        "running": False,
        "last_command": "",
        "started_at": 0.0,
        "last_output_at": time.time(),
        "last_idle_notice_at": 0.0,
        "timed_out": False,
        "loop_detected": False,
        "stop": False,
    }
    heartbeat_lock = threading.Lock()

    def heartbeat_worker() -> None:
        while True:
            time.sleep(max(1, heartbeat_seconds))
            with heartbeat_lock:
                if heartbeat_state["stop"]:
                    return
                if not heartbeat_state["running"]:
                    last_output_at = heartbeat_state.get("last_output_at", 0.0)
                    if not last_output_at:
                        continue
                    idle_elapsed = int(time.time() - last_output_at)
                    if (
                        role_idle_timeout_seconds > 0
                        and idle_elapsed >= role_idle_timeout_seconds
                        and process.poll() is None
                    ):
                        print(
                            f"[{role}] timeout: no model output for {idle_elapsed}s; terminating role process"
                        )
                        try:
                            process.terminate()
                        except OSError:
                            pass
                        heartbeat_state["timed_out"] = True
                        continue
                    if idle_elapsed >= heartbeat_seconds:
                        last_idle_notice_at = heartbeat_state.get("last_idle_notice_at", 0.0)
                        if (time.time() - last_idle_notice_at) >= heartbeat_seconds:
                            _activity = {
                                "DEVELOPER": "implementing",
                                "REVIEWER": "reviewing",
                                "TESTER": "running checks",
                                "PLANNER": "planning",
                                "ARCHITECT": "designing",
                            }.get(role, "processing")
                            print(f"[{role}] waiting for model response — {_activity} ({idle_elapsed}s)")
                            heartbeat_state["last_idle_notice_at"] = time.time()
                    continue
                cmd = heartbeat_state["last_command"]
                started = heartbeat_state["started_at"]
            elapsed = int(time.time() - started) if started else 0
            print(f"[{role}] working on {cmd} ({elapsed}s)")

    heartbeat_thread = threading.Thread(target=heartbeat_worker, daemon=True)
    heartbeat_thread.start()
    if task_step_hint:
        _activity = {
            "DEVELOPER": "implementing",
            "REVIEWER": "reviewing",
            "TESTER": "running checks",
            "PLANNER": "planning",
            "ARCHITECT": "designing",
        }.get(role, "processing")
        print(f"[{role}] {_activity}: {task_step_hint}")

    stdout_lines: list[str] = []
    try:
        if process.stdout is not None:
            expecting_token_value = False
            in_exec_block = False
            in_prompt_echo_block = False
            last_progress_update = ""
            active_command_hint = ""
            pending_section_header = ""
            pending_section_items: list[str] = []
            pending_section_lines = 0
            recent_progress_updates: list[str] = []

            def record_progress_update(update: str) -> bool:
                if not update:
                    return False
                recent_progress_updates.append(update)
                max_items = max(1, role_repeat_window * role_repeat_limit)
                if len(recent_progress_updates) > max_items:
                    del recent_progress_updates[: len(recent_progress_updates) - max_items]
                return has_repeating_sequence(
                    recent_progress_updates, role_repeat_window, role_repeat_limit
                )

            for line in process.stdout:
                with heartbeat_lock:
                    heartbeat_state["last_output_at"] = time.time()
                    heartbeat_state["last_idle_notice_at"] = 0.0
                clean_line = strip_ansi(line)
                stripped = clean_line.strip()

                # Claude stream-json mode: parse JSON events; only accumulate text content.
                if cli_tool == "claude" and stripped:
                    try:
                        event = json.loads(stripped)
                        event_type = event.get("type", "")

                        if event_type == "result":
                            result_text = event.get("result", "")
                            if result_text:
                                stdout_lines.append(result_text)
                            with heartbeat_lock:
                                heartbeat_state["running"] = False
                                heartbeat_state["last_command"] = ""
                                heartbeat_state["started_at"] = 0.0
                            active_command_hint = ""

                        elif event_type == "assistant":
                            content = event.get("message", {}).get("content", [])
                            for block in (content if isinstance(content, list) else []):
                                block_type = block.get("type", "")
                                if block_type == "tool_use":
                                    name = block.get("name", "")
                                    input_data = block.get("input", {})
                                    hint = name.lower() or "tool"
                                    if progress_only:
                                        verbose = describe_tool_from_json(name, input_data)
                                        if verbose:
                                            print(f"[{role}] {verbose}")
                                    with heartbeat_lock:
                                        heartbeat_state["running"] = True
                                        heartbeat_state["last_command"] = hint
                                        heartbeat_state["started_at"] = time.time()
                                    active_command_hint = hint
                                elif block_type == "text":
                                    text = block.get("text", "")
                                    if not text:
                                        continue
                                    stdout_lines.append(text)
                                    with heartbeat_lock:
                                        heartbeat_state["running"] = False
                                        heartbeat_state["last_command"] = ""
                                        heartbeat_state["started_at"] = 0.0
                                    active_command_hint = ""
                                    if progress_only:
                                        for text_line in text.splitlines():
                                            tstripped = text_line.strip()
                                            if not tstripped:
                                                continue
                                            if any(tstripped.startswith(pfx) for pfx in PROMPT_ECHO_LINE_PREFIXES):
                                                continue
                                            update = extract_progress_update(tstripped)
                                            if update and update != last_progress_update:
                                                print(f"[{role}] note: {update}")
                                                if record_progress_update(update):
                                                    print(f"[{role}] loop detected: repeating progress updates; terminating role process")
                                                    with heartbeat_lock:
                                                        heartbeat_state["loop_detected"] = True
                                                    try:
                                                        process.terminate()
                                                    except OSError:
                                                        pass
                                                    break
                                                last_progress_update = update
                        continue  # skip codex/text processing for all JSON events
                    except json.JSONDecodeError:
                        pass  # not JSON; fall through to text processing below

                stdout_lines.append(clean_line)

                if expecting_token_value:
                    expecting_token_value = False
                    continue
                if stripped == "tokens used":
                    expecting_token_value = True
                    continue

                # Keep console readable in default mode: show activity, suppress raw command output body.
                if progress_only:
                    # Suppress echoed role/task prompts from CLI stream.
                    prompt_echo_starts = (
                        stripped.startswith("SYSTEM ROLE INSTRUCTIONS:")
                        or stripped.startswith("TASK:")
                        or stripped in {"Responsibilities:", "Collaboration files:", "Rules:"}
                        or any(stripped.startswith(prefix) for prefix in PROMPT_ECHO_LINE_PREFIXES)
                    )
                    if suppress_prompt_echo and prompt_echo_starts:
                        in_prompt_echo_block = True
                        continue
                    if suppress_prompt_echo and in_prompt_echo_block:
                        if not stripped:
                            in_prompt_echo_block = False
                            continue
                        if stripped in {"thinking", "exec", "codex", "file update", "apply_patch", "tokens used"} or stripped.startswith("⏺"):
                            in_prompt_echo_block = False
                        else:
                            continue

                    # Claude plain-text fallback: ⏺/⎿ markers (non-stream-json mode).
                    if cli_tool == "claude":
                        if stripped.startswith("⏺"):
                            verbose = describe_claude_tool_call(stripped)
                            cmd_hint = command_hint_from_claude_tool(stripped) or "tool"
                            if verbose:
                                print(f"[{role}] {verbose}")
                            with heartbeat_lock:
                                heartbeat_state["running"] = True
                                heartbeat_state["last_command"] = cmd_hint
                                heartbeat_state["started_at"] = time.time()
                            active_command_hint = cmd_hint
                            continue
                        if stripped.startswith("⎿"):
                            continue
                        if active_command_hint:
                            with heartbeat_lock:
                                heartbeat_state["running"] = False
                                heartbeat_state["last_command"] = ""
                                heartbeat_state["started_at"] = 0.0
                            active_command_hint = ""

                    # Codex: exec block tracking.
                    if cli_tool != "claude":
                        if stripped == "exec":
                            in_exec_block = True
                            with heartbeat_lock:
                                heartbeat_state["running"] = False
                                heartbeat_state["last_command"] = ""
                                heartbeat_state["started_at"] = 0.0
                            continue
                        if in_exec_block and (
                            stripped.startswith("/bin/zsh -lc")
                            or stripped.startswith("/bin/bash -lc")
                        ):
                            cmd_hint = command_hint_from_shell_invocation(stripped)
                            if cmd_hint != active_command_hint:
                                print(f"[{role}] running: {cmd_hint}")
                                active_command_hint = cmd_hint
                            with heartbeat_lock:
                                heartbeat_state["running"] = True
                                heartbeat_state["last_command"] = (
                                    cmd_hint if progress_only else stripped
                                )
                                heartbeat_state["started_at"] = time.time()
                            continue
                        if in_exec_block and (
                            "succeeded in " in stripped
                            or "exited " in stripped
                            or "failed in " in stripped
                        ):
                            print(f"[{role}] {summarize_exec_completion(stripped)}")
                            with heartbeat_lock:
                                heartbeat_state["running"] = False
                                heartbeat_state["last_command"] = ""
                                heartbeat_state["started_at"] = 0.0
                            active_command_hint = ""
                            continue
                        if in_exec_block and stripped in {"thinking", "codex", "file update", "apply_patch"}:
                            in_exec_block = False
                            with heartbeat_lock:
                                heartbeat_state["running"] = False
                                heartbeat_state["last_command"] = ""
                                heartbeat_state["started_at"] = 0.0
                            active_command_hint = ""
                        elif in_exec_block:
                            continue

                    if stripped == "thinking":
                        print(f"[{role}] planning next step...")
                        continue

                if progress_only:
                    if pending_section_header:
                        item = extract_progress_section_item(stripped)
                        if item:
                            pending_section_items.append(item)
                            preview = " | ".join(pending_section_items[:2])
                            update = f"{pending_section_header} {preview}"
                            if update != last_progress_update:
                                print(f"[{role}] note: {update}")
                                last_progress_update = update
                                if record_progress_update(update):
                                    print(
                                        f"[{role}] loop detected: repeating progress updates; terminating role process"
                                    )
                                    with heartbeat_lock:
                                        heartbeat_state["loop_detected"] = True
                                    try:
                                        process.terminate()
                                    except OSError:
                                        pass
                                    break
                            if len(pending_section_items) >= 2:
                                pending_section_header = ""
                                pending_section_items = []
                                pending_section_lines = 0
                            continue

                        if not stripped:
                            pending_section_lines += 1
                            if pending_section_lines <= 2:
                                continue
                        pending_section_header = ""
                        pending_section_items = []
                        pending_section_lines = 0

                    update = extract_progress_update(stripped)
                    if update and update != last_progress_update:
                        print(f"[{role}] note: {update}")
                        if record_progress_update(update):
                            print(
                                f"[{role}] loop detected: repeating progress updates; terminating role process"
                            )
                            with heartbeat_lock:
                                heartbeat_state["loop_detected"] = True
                            try:
                                process.terminate()
                            except OSError:
                                pass
                            break
                        if update.endswith(":"):
                            pending_section_header = update
                            pending_section_items = []
                            pending_section_lines = 0
                        last_progress_update = update
                    continue

                if is_code_like_line(clean_line):
                    continue

                if should_print_line(clean_line, suppress_noise=suppress_noise, suppress_prompt_echo=suppress_prompt_echo):
                    print(f"[{role}] {clean_line}", end="")
    except KeyboardInterrupt:
        print(f"\n[{role}] interrupted by user, stopping active process...")
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        raise
    finally:
        with heartbeat_lock:
            heartbeat_state["stop"] = True

    return_code = process.wait()
    timed_out = heartbeat_state.get("timed_out", False)
    loop_detected = heartbeat_state.get("loop_detected", False)
    output_text = "".join(stdout_lines).strip()
    if timed_out:
        raise TimeoutError(
            f"{role} timed out after {role_idle_timeout_seconds}s without model output"
        )
    if loop_detected:
        raise RuntimeError(
            f"{role} loop detected: repeating progress update sequence "
            f"(window={role_repeat_window}, repeats={role_repeat_limit})"
        )
    if return_code != 0 and not output_text:
        raise RuntimeError(f"{role} failed with exit code {return_code}")
    if return_code != 0:
        print(
            f"[{role}] Warning: {cli_tool} returned exit code {return_code} but produced output; continuing."
        )
    return output_text


def write_state_snapshot(path: Path, title: str, body: str) -> None:
    updated_at = datetime.now().isoformat(timespec="seconds")
    content = (
        f"# {title}\n\n"
        f"Updated: {updated_at}\n\n"
        "## Current State\n"
        f"{body.strip()}\n"
    )
    path.write_text(content, encoding="utf-8")


def normalize_state_snapshot(path: Path, title: str) -> None:
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    if text.startswith(f"# {title}\n") and "## Current State" in text:
        return

    lines = text.splitlines()
    last_h2_idx = -1
    for idx, line in enumerate(lines):
        if line.startswith("## "):
            last_h2_idx = idx

    if last_h2_idx >= 0 and last_h2_idx + 1 < len(lines):
        body = "\n".join(lines[last_h2_idx + 1 :]).strip()
    else:
        body = text.strip()

    if not body:
        body = "(no updates yet)"
    write_state_snapshot(path, title, body)


def append_decision(path: Path, event: str) -> None:
    timestamp = datetime.now().isoformat(timespec="seconds")
    entry = f"- {timestamp} | {event}\n"
    header = "# Agent Decisions and Handoffs (Current)\n\n"

    if not path.exists():
        path.write_text(
            header + f"Updated: {timestamp}\n\n## Events\n" + entry,
            encoding="utf-8",
        )
        return

    text = path.read_text(encoding="utf-8")
    # If file is empty or only has the placeholder, start fresh.
    if "(no events yet)" in text or "## Events\n" not in text:
        path.write_text(
            header + f"Updated: {timestamp}\n\n## Events\n" + entry,
            encoding="utf-8",
        )
        return

    # Update the timestamp line and append the new entry.
    text = re.sub(r"^Updated: .*$", f"Updated: {timestamp}", text, count=1, flags=re.MULTILINE)
    path.write_text(text.rstrip() + "\n" + entry, encoding="utf-8")


def ensure_shared_files(
    cwd: Path, idea: str, guidelines: str, role_preferences: str
) -> dict[str, Path]:
    files = {
        "plan": cwd / "plan.md",
        "architecture": cwd / "architecture.md",
        "development": cwd / "development.md",
        "review": cwd / "review.md",
        "test_results": cwd / "test_results.md",
        "compliance": cwd / "compliance.md",
        "decisions_log": cwd / "decisions_log.md",
        "workflow_state": cwd / "workflow_state.json",
    }

    if not files["plan"].exists():
        files["plan"].write_text(
            "# Plan\n\n"
            f"## Inputs\n- Idea: {idea}\n- Guidelines: {guidelines}\n"
            f"- Role Preferences: {role_preferences if role_preferences else '(none)'}\n\n"
            "## Current Plan\n(To be written by planner)\n",
            encoding="utf-8",
        )
    if not files["architecture"].exists():
        files["architecture"].write_text(
            "# Architecture\n\n(To be written by architect)\n", encoding="utf-8"
        )
    if not files["development"].exists():
        files["development"].write_text(
            "# Development State\n\n(To be maintained as current state by developer)\n",
            encoding="utf-8",
        )
    if not files["review"].exists():
        files["review"].write_text(
            "# Review State\n\n(To be maintained as current state by reviewer)\n",
            encoding="utf-8",
        )
    if not files["test_results"].exists():
        files["test_results"].write_text(
            "# Test State\n\n(To be maintained as current state by tester)\n",
            encoding="utf-8",
        )
    if not files["compliance"].exists():
        files["compliance"].write_text(
            "# Compliance State\n\n(To be maintained as current state by compliance role)\n",
            encoding="utf-8",
        )
    if not files["decisions_log"].exists():
        files["decisions_log"].write_text(
            "# Agent Decisions and Handoffs (Current)\n\n(no events yet)\n## Events\n",
            encoding="utf-8",
        )
    if not files["workflow_state"].exists():
        files["workflow_state"].write_text("{}\n", encoding="utf-8")
    normalize_state_snapshot(files["development"], "Development State")
    normalize_state_snapshot(files["review"], "Review State")
    normalize_state_snapshot(files["test_results"], "Test State")
    normalize_state_snapshot(files["compliance"], "Compliance State")
    return files


def read_changes_request(cwd: Path, changes_file: str) -> tuple[Path, str]:
    path = (cwd / changes_file).resolve() if not Path(changes_file).is_absolute() else Path(changes_file).resolve()
    if path.exists():
        return path, path.read_text(encoding="utf-8").strip()
    return path, ""


def get_plan_progress(plan_path: Path) -> dict[str, object]:
    if not plan_path.exists():
        return {
            "pending_count": 0,
            "completed_count": 0,
            "next_step": "",
        }

    lines = plan_path.read_text(encoding="utf-8").splitlines()
    pending_count = 0
    completed_count = 0
    next_step = ""
    checkbox_pattern = re.compile(r"^\s*[-*]\s+\[( |x|X)\]\s+(.+)$")
    for raw_line in lines:
        match = checkbox_pattern.match(raw_line)
        if not match:
            continue
        status = match.group(1)
        step_text = match.group(2).strip()
        if status in {"x", "X"}:
            completed_count += 1
        else:
            pending_count += 1
            if not next_step:
                next_step = step_text
    return {
        "pending_count": pending_count,
        "completed_count": completed_count,
        "next_step": next_step,
    }


def mark_next_plan_step_done(plan_path: Path) -> str:
    if not plan_path.exists():
        return ""

    lines = plan_path.read_text(encoding="utf-8").splitlines()
    checkbox_pattern = re.compile(r"^(\s*[-*]\s+\[)( |x|X)(\]\s+)(.+)$")
    completed_step = ""
    for idx, raw_line in enumerate(lines):
        match = checkbox_pattern.match(raw_line)
        if not match:
            continue
        status = match.group(2)
        if status in {"x", "X"}:
            continue
        completed_step = match.group(4).strip()
        lines[idx] = f"{match.group(1)}x{match.group(3)}{match.group(4)}"
        break

    if completed_step:
        plan_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return completed_step


def read_workflow_state(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in data.items():
        if isinstance(value, str):
            out[key] = value
    return out


def write_workflow_state(
    path: Path,
    *,
    cycle: int,
    current_step: str,
    next_role: str,
    dev_status: str,
    review_status: str,
    test_status: str,
    compliance_status: str = "",
    safeguard_status: str = "",
) -> None:
    state = {
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "cycle": str(cycle),
        "current_step": current_step,
        "next_role": next_role,
        "dev_status": dev_status,
        "review_status": review_status,
        "test_status": test_status,
        "compliance_status": compliance_status,
        "safeguard_status": safeguard_status,
    }
    path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def infer_resume_role_from_state(state_path: Path, current_step: str) -> str:
    state = read_workflow_state(state_path)
    next_role = state.get("next_role", "DEVELOPER").upper()
    if next_role not in {"REVIEWER", "TESTER", "COMPLIANCE"}:
        return "DEVELOPER"
    state_step = state.get("current_step", "")
    if state_step != current_step:
        return "DEVELOPER"

    dev_status = state.get("dev_status", "").upper()
    review_status = state.get("review_status", "").upper()
    test_status = state.get("test_status", "").upper()
    if next_role == "REVIEWER":
        if dev_status in {"READY_FOR_REVIEW", "COMPLETE"}:
            return "REVIEWER"
        return "DEVELOPER"
    if next_role == "TESTER":
        if dev_status in {"READY_FOR_REVIEW", "COMPLETE"} and review_status == "APPROVED":
            return "TESTER"
        return "DEVELOPER"
    if next_role == "COMPLIANCE":
        if (
            dev_status in {"READY_FOR_REVIEW", "COMPLETE"}
            and review_status == "APPROVED"
            and test_status == "PASS"
        ):
            return "COMPLIANCE"
        return "DEVELOPER"
    return "DEVELOPER"


def run_planner_architect(
    cwd: Path,
    idea: str,
    guidelines: str,
    role_preferences: str,
    changes_path: Path,
    change_request: str,
    shared: dict[str, Path],
    reason: str,
    cycle: int,
    triggered_by: str,
    agents_text: str,
    cli_tool: str = "codex",
) -> tuple[str, str]:
    append_decision(
        shared["decisions_log"],
        f"cycle={cycle} | handoff={triggered_by}->PLANNER | reason={reason}",
    )
    planner_task = f"""
Project idea:
{idea}

Rough stack/tool guidance:
{guidelines}

Active change request (from {changes_path}):
{change_request if change_request else "(none)"}

Trigger reason for replanning:
{reason}

You are responsible for writing and refining plan.md in this directory:
{cwd}

Produce a practical implementation plan and milestone structure in plan.md.
If change requests are present, update the implementation plan to address them.
Include a short human-readable summary in your plain-text response.
"""
    planner_out = run_agent_cli(
        "PLANNER",
        with_governance_contract(PLANNER_SYSTEM, role_preferences, agents_text),
        planner_task,
        cwd,
        cli_tool,
    )
    planner_status = extract_marker(planner_out, "PLAN_STATUS", ["READY"], "READY")
    append_decision(
        shared["decisions_log"],
        f"cycle={cycle} | role=PLANNER | plan_status={planner_status} | replan_required=NO | handoff=PLANNER->ARCHITECT",
    )

    architect_task = f"""
Project idea:
{idea}

Guidelines:
{guidelines}

Active change request (from {changes_path}):
{change_request if change_request else "(none)"}

Trigger reason for architecture refinement:
{reason}

Use plan.md as input and produce/refine architecture.md in this directory:
{cwd}

If architecture changes implementation order, update plan.md accordingly.
If change requests are present, refine architecture decisions to satisfy them.
Include a concise human-readable summary in your plain-text response.
"""
    architect_out = run_agent_cli(
        "ARCHITECT",
        with_governance_contract(ARCHITECT_SYSTEM, role_preferences, agents_text),
        architect_task,
        cwd,
        cli_tool,
    )
    arch_status = extract_marker(architect_out, "ARCH_STATUS", ["READY"], "READY")
    append_decision(
        shared["decisions_log"],
        f"cycle={cycle} | role=ARCHITECT | arch_status={arch_status} | replan_required=NO | handoff=ARCHITECT->DEVELOPER",
    )
    return planner_out, architect_out


def main() -> int:
    args = parse_args()
    cwd = Path.cwd().resolve()
    idea, guidelines, role_preferences = ensure_inputs(args, cwd)
    agents_text, policy_text, agents_path, policy_path = load_governance_context(cwd, args.policy_file)
    changes_path, change_request = read_changes_request(cwd, args.changes_file)

    shared = ensure_shared_files(cwd, idea, guidelines, role_preferences)

    print(f"\nAgentic workflow started (CLI: {args.cli}).")
    print_full_inputs = os.environ.get("AGENT_PRINT_INPUTS_FULL", "0").strip() == "1"
    if print_full_inputs:
        print(f"Idea: {idea}")
        print(f"Guidelines: {guidelines}")
    else:
        print(f"Idea (summary): {summarize_input_for_log(idea)}")
        print(f"Guidelines (summary): {summarize_input_for_log(guidelines)}")
    print(
        "Role preferences: "
        + (role_preferences if role_preferences else "(none provided)")
    )
    print(
        f"Change request file: {changes_path} "
        + ("(loaded)" if change_request else "(not found or empty)")
    )
    print(
        "Enforce Terraform apply: "
        + ("enabled" if args.enforce_apply else "disabled")
    )
    print(
        "Strict policy gates: "
        + ("enabled" if args.strict_policy_gates else "disabled")
    )
    print(
        f"Governance files: AGENTS.md={'present' if agents_path.exists() else 'missing'}, "
        + f"{policy_path.name}={'present' if policy_path.exists() else 'missing'}"
    )
    print(f"Working directory: {cwd}")
    print("Knowledge files:")
    for path in shared.values():
        print(f"- {path}")

    print(
        "\nPlanner/architect are on-demand only and will run when "
        "DEVELOPER/REVIEWER/TESTER flags REPLAN_REQUIRED: YES."
    )

    initial_progress = get_plan_progress(shared["plan"])
    if initial_progress["pending_count"] == 0 and initial_progress["completed_count"] == 0:
        reason = (
            "No checklist steps found in plan.md. Create a practical step-by-step plan "
            "using markdown checkboxes (- [ ])."
        )
        print("[GATE] Initial planning bootstrap required.")
        run_planner_architect(
            cwd=cwd,
            idea=idea,
            guidelines=guidelines,
            role_preferences=role_preferences,
            changes_path=changes_path,
            change_request=change_request,
            shared=shared,
            reason=reason,
            cycle=0,
            triggered_by="SYSTEM",
            agents_text=agents_text,
            cli_tool=args.cli,
        )

    refreshed_progress = get_plan_progress(shared["plan"])
    current_resume_step = str(refreshed_progress["next_step"] or "").strip()
    append_decision(
        shared["decisions_log"],
        "cycle=0 | plan_progress | "
        f"completed={refreshed_progress['completed_count']} | "
        f"pending={refreshed_progress['pending_count']} | "
        f"next_step={refreshed_progress['next_step'] if refreshed_progress['next_step'] else '(none)'}",
    )
    next_role = infer_resume_role_from_state(shared["workflow_state"], current_resume_step)
    append_decision(
        shared["decisions_log"],
        f"cycle=0 | workflow_start | handoff=SYSTEM->{next_role} | note=planner_architect_on_demand",
    )
    print("Resume role: workflow_state=" + next_role)

    dev_status = "IN_PROGRESS"
    review_status = "CHANGES_REQUIRED"
    test_status = "FAIL"
    compliance_status = "VIOLATIONS"
    safeguard_status = "FAIL"
    last_gate_signature: tuple[str, str, str, str, str, str, bool] | None = None
    stagnation_count = 0

    def record_stagnation_and_maybe_stop(
        cycle: int,
        current_step: str,
        dev_status: str,
        review_status: str,
        test_status: str,
        compliance_status: str,
        safeguard_status: str,
        apply_ok: bool,
    ) -> bool:
        nonlocal last_gate_signature, stagnation_count
        current_gate_signature = (
            current_step,
            dev_status,
            review_status,
            test_status,
            compliance_status,
            safeguard_status,
            apply_ok,
        )
        if current_gate_signature == last_gate_signature:
            stagnation_count += 1
        else:
            stagnation_count = 1
            last_gate_signature = current_gate_signature

        if stagnation_count >= max(1, args.max_stagnation_cycles):
            reason = (
                "Repeated identical gate outcomes without step progress; stopping to avoid loop. "
                f"step={current_step}; dev={dev_status}; review={review_status}; "
                f"test={test_status}; compliance={compliance_status}; safeguards={safeguard_status}; "
                f"apply_ok={str(apply_ok).upper()}; "
                f"stagnation_cycles={stagnation_count}"
            )
            print(f"[GATE] {reason}")
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | workflow_end | result=STALLED | reason={reason}",
            )
            return True
        return False

    for cycle in range(1, args.max_cycles + 1):
        print(f"\n{'#' * 80}")
        print(f"CYCLE {cycle} / {args.max_cycles}")
        print(f"{'#' * 80}\n")

        cycle_progress = get_plan_progress(shared["plan"])
        if cycle_progress["pending_count"] == 0:
            print("No pending plan checklist steps. Workflow complete.")
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | workflow_end | result=SUCCESS | reason=no_pending_plan_steps",
            )
            break
        current_step = str(cycle_progress["next_step"] or "").strip()
        print(f"Current plan step: {current_step}")
        append_decision(
            shared["decisions_log"],
            f"cycle={cycle} | plan_step_active={current_step}",
        )

        developer_out = ""
        reviewer_out = ""
        tester_out = ""
        compliance_out = ""
        apply_ok = False

        if next_role == "DEVELOPER":
            compliance_status = "VIOLATIONS"
            safeguard_status = "FAIL"
            developer_task = f"""
Cycle {cycle}.

Current implementation step (from plan checklist):
{current_step}

Read and follow:
- plan.md
- architecture.md
- review.md
- test_results.md
- compliance.md

Active change request (from {changes_path}):
{change_request if change_request else "(none)"}

Terraform apply enforcement:
{"ENABLED: You must run make tf-apply and capture outcome evidence in development.md and test_results.md." if args.enforce_apply else "DISABLED"}

Working directory:
{cwd}

Implement code directly in current working directory.
Update development.md as a current state snapshot (what is true now).
If a change request exists, prioritize implementing it while preserving existing working behavior.
If needed, update plan.md or architecture.md with rationale.
Focus only on completing the current implementation step above.
Do not start subsequent checklist steps in this cycle.
If high-level plan/architecture changes are needed, set REPLAN_REQUIRED: YES.
Return plain text summary and a DEV_STATUS marker.
"""
            developer_out = run_agent_cli(
                "DEVELOPER",
                with_governance_contract(DEVELOPER_SYSTEM, role_preferences, agents_text),
                developer_task,
                cwd,
                args.cli,
            )
            write_state_snapshot(shared["development"], "Development State", developer_out)
            dev_status = extract_marker(
                developer_out,
                "DEV_STATUS",
                ["IN_PROGRESS", "READY_FOR_REVIEW", "COMPLETE", "BLOCKED"],
                "IN_PROGRESS",
            )
            dev_replan = extract_yes_no_marker(developer_out, "REPLAN_REQUIRED", default="NO")
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | role=DEVELOPER | dev_status={dev_status} | replan_required={dev_replan}",
            )
            if dev_replan == "YES" or should_replan(developer_out):
                reason = (
                    f"Developer cycle {cycle} requested high-level planning/architecture change."
                )
                print(f"[GATE] {reason}")
                run_planner_architect(
                    cwd=cwd,
                    idea=idea,
                    guidelines=guidelines,
                    role_preferences=role_preferences,
                    changes_path=changes_path,
                    change_request=change_request,
                    shared=shared,
                    reason=reason,
                    cycle=cycle,
                    triggered_by="DEVELOPER",
                    agents_text=agents_text,
                    cli_tool=args.cli,
                )
                next_role = "DEVELOPER"
                write_workflow_state(
                    shared["workflow_state"],
                    cycle=cycle,
                    current_step=current_step,
                    next_role=next_role,
                    dev_status=dev_status,
                    review_status=review_status,
                    test_status=test_status,
                )
                if record_stagnation_and_maybe_stop(
                    cycle, current_step, dev_status, review_status, test_status, compliance_status, safeguard_status, apply_ok
                ):
                    break
                continue
            if dev_status not in {"READY_FOR_REVIEW", "COMPLETE"}:
                append_decision(
                    shared["decisions_log"],
                    f"cycle={cycle} | handoff=DEVELOPER->DEVELOPER | reason=dev_status_{dev_status}",
                )
                next_role = "DEVELOPER"
                write_workflow_state(
                    shared["workflow_state"],
                    cycle=cycle,
                    current_step=current_step,
                    next_role=next_role,
                    dev_status=dev_status,
                    review_status=review_status,
                    test_status=test_status,
                )
                if record_stagnation_and_maybe_stop(
                    cycle, current_step, dev_status, review_status, test_status, compliance_status, safeguard_status, apply_ok
                ):
                    break
                continue
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | handoff=DEVELOPER->REVIEWER",
            )
            next_role = "REVIEWER"
            write_workflow_state(
                shared["workflow_state"],
                cycle=cycle,
                current_step=current_step,
                next_role=next_role,
                dev_status=dev_status,
                review_status=review_status,
                test_status=test_status,
            )
        elif next_role == "REVIEWER":
            print("[RESUME] Skipping developer this cycle and resuming at reviewer.")
            dev_status = "READY_FOR_REVIEW"
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | resume | handoff=DEVELOPER->REVIEWER",
            )
        elif next_role == "TESTER":
            print("[RESUME] Skipping developer/reviewer this cycle and resuming at tester.")
            dev_status = "READY_FOR_REVIEW"
            review_status = "APPROVED"
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | resume | handoff=REVIEWER->TESTER",
            )
        elif next_role == "COMPLIANCE":
            print("[RESUME] Skipping developer/reviewer/tester this cycle and resuming at compliance.")
            dev_status = "READY_FOR_REVIEW"
            review_status = "APPROVED"
            test_status = "PASS"
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | resume | handoff=TESTER->COMPLIANCE",
            )

        if next_role in {"REVIEWER"}:
            reviewer_task = f"""
Review cycle {cycle}.

Current implementation step (from plan checklist):
{current_step}

Read:
- plan.md
- architecture.md
- development.md
- compliance.md

Active change request (from {changes_path}):
{change_request if change_request else "(none)"}

Review implementation in:
{cwd}

Write findings in review.md as a current state snapshot with blocking and non-blocking sections.
Review whether the change request is correctly implemented without regressions.
Review only the current implementation step above and confirm whether it is ready for testing.
If high-level plan/architecture changes are needed, set REPLAN_REQUIRED: YES.
Return plain text summary and REVIEW_STATUS marker.
"""
            reviewer_out = run_agent_cli(
                "REVIEWER",
                with_governance_contract(REVIEWER_SYSTEM, role_preferences, agents_text),
                reviewer_task,
                cwd,
                args.cli,
            )
            write_state_snapshot(shared["review"], "Review State", reviewer_out)
            review_status = extract_marker(
                reviewer_out,
                "REVIEW_STATUS",
                ["APPROVED", "CHANGES_REQUIRED"],
                "CHANGES_REQUIRED",
            )
            review_replan = extract_yes_no_marker(reviewer_out, "REPLAN_REQUIRED", default="NO")
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | role=REVIEWER | review_status={review_status} | replan_required={review_replan}",
            )
            if review_replan == "YES" or should_replan(reviewer_out):
                reason = (
                    f"Reviewer cycle {cycle} requested high-level planning/architecture change."
                )
                print(f"[GATE] {reason}")
                run_planner_architect(
                    cwd=cwd,
                    idea=idea,
                    guidelines=guidelines,
                    role_preferences=role_preferences,
                    changes_path=changes_path,
                    change_request=change_request,
                    shared=shared,
                    reason=reason,
                    cycle=cycle,
                    triggered_by="REVIEWER",
                    agents_text=agents_text,
                    cli_tool=args.cli,
                )
                next_role = "DEVELOPER"
                write_workflow_state(
                    shared["workflow_state"],
                    cycle=cycle,
                    current_step=current_step,
                    next_role=next_role,
                    dev_status=dev_status,
                    review_status=review_status,
                    test_status=test_status,
                )
                if record_stagnation_and_maybe_stop(
                    cycle, current_step, dev_status, review_status, test_status, compliance_status, safeguard_status, apply_ok
                ):
                    break
                continue

            if review_status != "APPROVED":
                print(
                    f"Cycle {cycle} gate -> dev={dev_status}, review={review_status}, "
                    "tester=SKIPPED (review not approved)"
                )
                append_decision(
                    shared["decisions_log"],
                    f"cycle={cycle} | handoff=REVIEWER->DEVELOPER | reason=review_status_{review_status}",
                )
                next_role = "DEVELOPER"
                write_workflow_state(
                    shared["workflow_state"],
                    cycle=cycle,
                    current_step=current_step,
                    next_role=next_role,
                    dev_status=dev_status,
                    review_status=review_status,
                    test_status=test_status,
                )
                if record_stagnation_and_maybe_stop(
                    cycle, current_step, dev_status, review_status, test_status, compliance_status, safeguard_status, apply_ok
                ):
                    break
                continue
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | handoff=REVIEWER->TESTER",
            )
            next_role = "TESTER"
            write_workflow_state(
                shared["workflow_state"],
                cycle=cycle,
                current_step=current_step,
                next_role=next_role,
                dev_status=dev_status,
                review_status=review_status,
                test_status=test_status,
            )

        if next_role == "TESTER":
            tester_task = f"""
Test cycle {cycle}.

Current implementation step (from plan checklist):
{current_step}

Read:
- plan.md
- architecture.md
- development.md
- review.md
- compliance.md

Active change request (from {changes_path}):
{change_request if change_request else "(none)"}

Terraform apply enforcement:
{"ENABLED: Verify apply was executed successfully this run. If not, mark fail and explain." if args.enforce_apply else "DISABLED"}

Run relevant checks in:
{cwd}

Write command outputs and concise summary in test_results.md as the current verification state.
Include validation focused on the requested changes.
Validate only the current implementation step above in this cycle.
If high-level plan/architecture changes are needed, set REPLAN_REQUIRED: YES.
Return plain text summary and TEST_STATUS marker.
"""
            tester_out = run_agent_cli(
                "TESTER",
                with_governance_contract(TESTER_SYSTEM, role_preferences, agents_text),
                tester_task,
                cwd,
                args.cli,
            )
            test_status = extract_marker(tester_out, "TEST_STATUS", ["PASS", "FAIL"], "FAIL")
            test_replan = extract_yes_no_marker(tester_out, "REPLAN_REQUIRED", default="NO")
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | role=TESTER | test_status={test_status} | replan_required={test_replan}",
            )
            if test_replan == "YES" or should_replan(tester_out):
                reason = (
                    f"Tester cycle {cycle} requested high-level planning/architecture change."
                )
                print(f"[GATE] {reason}")
                run_planner_architect(
                    cwd=cwd,
                    idea=idea,
                    guidelines=guidelines,
                    role_preferences=role_preferences,
                    changes_path=changes_path,
                    change_request=change_request,
                    shared=shared,
                    reason=reason,
                    cycle=cycle,
                    triggered_by="TESTER",
                    agents_text=agents_text,
                    cli_tool=args.cli,
                )
                next_role = "DEVELOPER"
                write_workflow_state(
                    shared["workflow_state"],
                    cycle=cycle,
                    current_step=current_step,
                    next_role=next_role,
                    dev_status=dev_status,
                    review_status=review_status,
                    test_status=test_status,
                    compliance_status=compliance_status,
                    safeguard_status=safeguard_status,
                )
                if record_stagnation_and_maybe_stop(
                    cycle, current_step, dev_status, review_status, test_status, compliance_status, safeguard_status, apply_ok
                ):
                    break
                continue

            apply_ok = detect_apply_success(developer_out, reviewer_out, tester_out)
            if args.enforce_apply and not apply_ok:
                test_status = "FAIL"
                msg = (
                    "Terraform apply enforcement is enabled, but no successful tf-apply evidence "
                    "was found in this cycle outputs."
                )
                print(f"[GATE] {msg}")
                tester_out = tester_out.strip() + "\n\nApply Enforcement Gate: FAIL\n" + msg
                append_decision(
                    shared["decisions_log"],
                    f"cycle={cycle} | gate=APPLY_ENFORCEMENT | result=FAIL | handoff=TESTER->DEVELOPER",
                )
            write_state_snapshot(shared["test_results"], "Test State", tester_out)
            if test_status == "PASS":
                append_decision(
                    shared["decisions_log"],
                    f"cycle={cycle} | handoff=TESTER->COMPLIANCE",
                )
                next_role = "COMPLIANCE"
                write_workflow_state(
                    shared["workflow_state"],
                    cycle=cycle,
                    current_step=current_step,
                    next_role=next_role,
                    dev_status=dev_status,
                    review_status=review_status,
                    test_status=test_status,
                    compliance_status=compliance_status,
                    safeguard_status=safeguard_status,
                )
            else:
                next_role = "DEVELOPER"

        if next_role == "COMPLIANCE":
            compliance_task = f"""
Compliance cycle {cycle}.

Current implementation step (from plan checklist):
{current_step}

Read:
- AGENTS.md
- {policy_path.name}
- plan.md
- architecture.md
- development.md
- review.md
- test_results.md

Active change request (from {changes_path}):
{change_request if change_request else "(none)"}

Repository path:
{cwd}

Assess coding-style consistency, compliance obligations, and safeguard coverage.
Ensure reviewer and tester evidence is sufficient for production confidence.
Write compliance.md with blocking and non-blocking policy findings.
If high-level plan/architecture changes are needed, set REPLAN_REQUIRED: YES.
Return plain text summary and compliance markers.
"""
            compliance_out = run_agent_cli(
                "COMPLIANCE",
                with_governance_contract(COMPLIANCE_SYSTEM, role_preferences, agents_text, policy_text),
                compliance_task,
                cwd,
                args.cli,
            )
            compliance_status = extract_marker(
                compliance_out,
                "COMPLIANCE_STATUS",
                ["APPROVED", "VIOLATIONS"],
                "VIOLATIONS",
            )
            safeguard_status = extract_marker(
                compliance_out,
                "SAFEGUARD_STATUS",
                ["PASS", "FAIL"],
                "FAIL",
            )
            compliance_replan = extract_yes_no_marker(compliance_out, "REPLAN_REQUIRED", default="NO")

            secret_findings = detect_sensitive_findings(cwd)
            if secret_findings:
                compliance_status = "VIOLATIONS"
                safeguard_status = "FAIL"
                evidence = "Sensitive-content scan findings:\n- " + "\n- ".join(secret_findings)
                compliance_out = compliance_out.strip() + "\n\n" + evidence
                append_decision(
                    shared["decisions_log"],
                    f"cycle={cycle} | gate=SENSITIVE_SCAN | result=FAIL | findings={len(secret_findings)}",
                )
            write_state_snapshot(shared["compliance"], "Compliance State", compliance_out)
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | role=COMPLIANCE | compliance_status={compliance_status} | safeguard_status={safeguard_status} | replan_required={compliance_replan}",
            )
            if compliance_replan == "YES" or should_replan(compliance_out):
                reason = (
                    f"Compliance cycle {cycle} requested high-level planning/architecture change."
                )
                print(f"[GATE] {reason}")
                run_planner_architect(
                    cwd=cwd,
                    idea=idea,
                    guidelines=guidelines,
                    role_preferences=role_preferences,
                    changes_path=changes_path,
                    change_request=change_request,
                    shared=shared,
                    reason=reason,
                    cycle=cycle,
                    triggered_by="COMPLIANCE",
                    agents_text=agents_text,
                    cli_tool=args.cli,
                )
                next_role = "DEVELOPER"
                write_workflow_state(
                    shared["workflow_state"],
                    cycle=cycle,
                    current_step=current_step,
                    next_role=next_role,
                    dev_status=dev_status,
                    review_status=review_status,
                    test_status=test_status,
                    compliance_status=compliance_status,
                    safeguard_status=safeguard_status,
                )
                if record_stagnation_and_maybe_stop(
                    cycle, current_step, dev_status, review_status, test_status, compliance_status, safeguard_status, apply_ok
                ):
                    break
                continue

        policy_gate_ok = compliance_status == "APPROVED" and safeguard_status == "PASS"
        if not args.strict_policy_gates and (compliance_status or safeguard_status):
            policy_gate_ok = True

        done = (
            review_status == "APPROVED"
            and test_status == "PASS"
            and dev_status in {"READY_FOR_REVIEW", "COMPLETE"}
            and policy_gate_ok
        )

        print(
            f"Cycle {cycle} gate -> dev={dev_status}, review={review_status}, "
            f"test={test_status}, compliance={compliance_status}, safeguards={safeguard_status}, apply_ok={apply_ok}"
        )
        next_handoff = "COMPLETE" if done else "COMPLIANCE->DEVELOPER"
        append_decision(
            shared["decisions_log"],
            f"cycle={cycle} | gate=DELIVERY | done={str(done).upper()} | policy_gate_ok={str(policy_gate_ok).upper()} | apply_ok={str(apply_ok).upper()} | handoff={next_handoff}",
        )

        if done:
            stagnation_count = 0
            last_gate_signature = None
            completed_step = mark_next_plan_step_done(shared["plan"])
            if completed_step:
                print(f"Completed plan step: {completed_step}")
                append_decision(
                    shared["decisions_log"],
                    f"cycle={cycle} | plan_step_completed={completed_step}",
                )
            progress_after = get_plan_progress(shared["plan"])
            append_decision(
                shared["decisions_log"],
                "cycle="
                + str(cycle)
                + " | plan_progress | "
                + f"completed={progress_after['completed_count']} | "
                + f"pending={progress_after['pending_count']} | "
                + "next_step="
                + (
                    progress_after["next_step"]
                    if progress_after["next_step"]
                    else "(none)"
                ),
            )
            if progress_after["pending_count"] == 0:
                print("\nDelivery gates satisfied. All plan steps completed.")
                append_decision(
                    shared["decisions_log"],
                    f"cycle={cycle} | workflow_end | result=SUCCESS",
                )
                write_workflow_state(
                    shared["workflow_state"],
                    cycle=cycle,
                    current_step="",
                    next_role="COMPLETE",
                    dev_status=dev_status,
                    review_status=review_status,
                    test_status=test_status,
                    compliance_status=compliance_status,
                    safeguard_status=safeguard_status,
                )
                break
            print("Step validated. Proceeding to next plan step.")
            append_decision(
                shared["decisions_log"],
                f"cycle={cycle} | handoff=TESTER->DEVELOPER | reason=next_plan_step",
            )
            next_role = "DEVELOPER"
            write_workflow_state(
                shared["workflow_state"],
                cycle=cycle,
                current_step=str(progress_after["next_step"] or "").strip(),
                next_role=next_role,
                dev_status=dev_status,
                review_status=review_status,
                test_status=test_status,
                compliance_status=compliance_status,
                safeguard_status=safeguard_status,
            )
            continue

        next_role = "DEVELOPER"
        write_workflow_state(
            shared["workflow_state"],
            cycle=cycle,
            current_step=current_step,
            next_role=next_role,
            dev_status=dev_status,
            review_status=review_status,
            test_status=test_status,
            compliance_status=compliance_status,
            safeguard_status=safeguard_status,
        )
        if record_stagnation_and_maybe_stop(
            cycle, current_step, dev_status, review_status, test_status, compliance_status, safeguard_status, apply_ok
        ):
            break
    else:
        print("\nMax cycles reached before full completion gates were satisfied.")
        append_decision(
            shared["decisions_log"],
            f"cycle={args.max_cycles} | workflow_end | result=MAX_CYCLES_REACHED",
        )

    print("\nFinal artifacts:")
    for path in shared.values():
        print(f"- {path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting cleanly.")
        sys.exit(130)
    except Exception as exc:
        print(f"Fatal error: {exc}")
        sys.exit(1)

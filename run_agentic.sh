#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${WORKSPACE_DIR:-$PWD}"
CLI_TOOL="codex"

usage() {
  cat <<'EOF'
Usage:
  ./run_agentic.sh [--cli codex|claude] [--workspace DIR] [main.py args...]

Description:
  Runs main.py with CLI role subprocesses configured for workspace-write access.
  Code is generated in the current working directory (or --workspace DIR).

Examples:
  ./run_agentic.sh --idea "Build a notes API" --guidelines "Python, FastAPI, pytest"
  ./run_agentic.sh --cli claude --idea "Build a notes API" --guidelines "Python, FastAPI, pytest"
  ./run_agentic.sh --brief-file ./project_brief.md
  ./run_agentic.sh --workspace /tmp/demo --idea "CLI tool" --guidelines "Go + cobra"

Options:
  --cli codex|claude     CLI tool to use (default: codex)
  --workspace DIR        Working directory for code generation (default: current directory)

Notes:
  - --brief-file points to a markdown brief with ## Idea and ## Guidelines sections.
  - Optional: add ## Role Preferences (or ## Project Structure Preferences) to inject shared constraints into every role system prompt.
  - Policy controls can be passed through to main.py: --policy-file <path> and --[no-]strict-policy-gates.
  - Subsequent change requests can be put in changes.md (or pass --changes-file <path>).
  - Optional extra CLI flags can be supplied via AGENT_CLI_FLAGS_EXTRA.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--cli" ]]; then
  if [[ -z "${2:-}" ]]; then
    echo "Missing value for --cli" >&2
    exit 1
  fi
  if [[ "$2" != "codex" && "$2" != "claude" ]]; then
    echo "Invalid value for --cli: $2 (must be 'codex' or 'claude')" >&2
    exit 1
  fi
  CLI_TOOL="$2"
  shift 2
fi

if [[ "${1:-}" == "--workspace" ]]; then
  if [[ -z "${2:-}" ]]; then
    echo "Missing value for --workspace" >&2
    exit 1
  fi
  WORKSPACE_DIR="$2"
  shift 2
fi

if ! command -v "$CLI_TOOL" >/dev/null 2>&1; then
  echo "$CLI_TOOL CLI not found in PATH." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found in PATH." >&2
  exit 1
fi

WORKSPACE_DIR="$(cd "$WORKSPACE_DIR" && pwd)"
cd "$WORKSPACE_DIR"

# Build CLI-specific flags
if [[ "$CLI_TOOL" == "claude" ]]; then
  DEFAULT_FLAGS=(
    --dangerously-skip-permissions
  )
else
  # codex
  DEFAULT_FLAGS=(
    --dangerously-bypass-approvals-and-sandbox
    --skip-git-repo-check
    --cd "$WORKSPACE_DIR"
    --add-dir "$WORKSPACE_DIR"
  )
fi

# Optional additive flags from user environment (with backward compatibility).
EXTRA_FLAGS="${AGENT_CLI_FLAGS_EXTRA:-}"
if [[ -z "$EXTRA_FLAGS" && -n "${CODEX_E_FLAGS_EXTRA:-}" ]]; then
  # Backward compatibility: fall back to CODEX_E_FLAGS_EXTRA
  EXTRA_FLAGS="${CODEX_E_FLAGS_EXTRA}"
fi

if [[ -n "$EXTRA_FLAGS" ]]; then
  AGENT_CLI_FLAGS="$(printf '%q ' "${DEFAULT_FLAGS[@]}") ${EXTRA_FLAGS}"
else
  AGENT_CLI_FLAGS="$(printf '%q ' "${DEFAULT_FLAGS[@]}")"
fi
export AGENT_CLI_FLAGS

echo "CLI tool: $CLI_TOOL"
echo "Workspace: $WORKSPACE_DIR"
echo "Injected CLI flags: $AGENT_CLI_FLAGS"
echo "Running: python3 $SCRIPT_DIR/main.py --cli $CLI_TOOL $*"

exec python3 "$SCRIPT_DIR/main.py" --cli "$CLI_TOOL" "$@"

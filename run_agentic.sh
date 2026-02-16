#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${WORKSPACE_DIR:-$PWD}"

usage() {
  cat <<'EOF'
Usage:
  ./run_agentic.sh [--workspace DIR] [main.py args...]

Description:
  Runs main.py with Codex role subprocesses configured for workspace-write access.
  Code is generated in the current working directory (or --workspace DIR).

Examples:
  ./run_agentic.sh --idea "Build a notes API" --guidelines "Python, FastAPI, pytest"
  ./run_agentic.sh --brief-file ./project_brief.md
  ./run_agentic.sh --workspace /tmp/demo --idea "CLI tool" --guidelines "Go + cobra"

Notes:
  - --brief-file points to a markdown brief with ## Idea and ## Guidelines sections.
  - Optional extra Codex flags can be supplied via CODEX_E_FLAGS_EXTRA.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--workspace" ]]; then
  if [[ -z "${2:-}" ]]; then
    echo "Missing value for --workspace" >&2
    exit 1
  fi
  WORKSPACE_DIR="$2"
  shift 2
fi

if ! command -v codex >/dev/null 2>&1; then
  echo "codex CLI not found in PATH." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found in PATH." >&2
  exit 1
fi

WORKSPACE_DIR="$(cd "$WORKSPACE_DIR" && pwd)"
cd "$WORKSPACE_DIR"


DEFAULT_FLAGS=(
  --sandbox workspace-write
  --ask-for-approval on-request
  --skip-git-repo-check
  --cd "$WORKSPACE_DIR"
  --add-dir "$WORKSPACE_DIR"
)

# Optional additive flags from user environment.
if [[ -n "${CODEX_E_FLAGS_EXTRA:-}" ]]; then
  CODEX_E_FLAGS="$(printf '%q ' "${DEFAULT_FLAGS[@]}") ${CODEX_E_FLAGS_EXTRA}"
else
  CODEX_E_FLAGS="$(printf '%q ' "${DEFAULT_FLAGS[@]}")"
fi
export CODEX_E_FLAGS

echo "Workspace: $WORKSPACE_DIR"
echo "Injected codex flags: $CODEX_E_FLAGS"
echo "Running: python3 $SCRIPT_DIR/main.py $*"

exec python3 "$SCRIPT_DIR/main.py" "$@"

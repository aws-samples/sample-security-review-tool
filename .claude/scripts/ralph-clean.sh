#!/bin/bash
set -euo pipefail

readonly DEFAULT_MAX_ITERATIONS=10
readonly PASS_MARKER="RALPH_CLEAN_PASS"
readonly FIXED_MARKER="RALPH_CLEAN_FIXED"
readonly NATIVE_PASS="Clean Code Analysis: PASS"

readonly CYAN='\033[0;36m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly RED='\033[0;31m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [options] <module-path>

Repeatedly runs the /clean-code skill against a module until zero
violations remain or the iteration limit is reached.

Arguments:
  <module-path>          File or directory to clean (e.g. src/hooks/)

Options:
  -m, --max-iterations N  Maximum loop iterations (default: $DEFAULT_MAX_ITERATIONS)
  -h, --help              Show this help message
EOF
    exit 1
}

log_info()    { echo -e "${CYAN}$1${NC}"; }
log_success() { echo -e "${GREEN}$1${NC}"; }
log_warning() { echo -e "${YELLOW}$1${NC}"; }
log_error()   { echo -e "${RED}$1${NC}" >&2; }
log_header()  { echo -e "\n${MAGENTA}${BOLD}$1${NC}"; }

max_iterations="$DEFAULT_MAX_ITERATIONS"
module_path=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--max-iterations)
            max_iterations="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            log_error "Unknown option: $1"
            usage
            ;;
        *)
            module_path="$1"
            shift
            ;;
    esac
done

if [[ -z "$module_path" ]]; then
    log_error "Error: Module path is required."
    usage
fi

if [[ ! -e "$module_path" ]]; then
    log_error "Error: Path does not exist: $module_path"
    exit 1
fi

if ! command -v claude &>/dev/null; then
    log_error "Error: 'claude' CLI not found in PATH."
    exit 1
fi

if ! command -v jq &>/dev/null; then
    log_error "Error: 'jq' is required but not found in PATH."
    exit 1
fi

if ! [[ "$max_iterations" =~ ^[1-9][0-9]*$ ]]; then
    log_error "Error: Max iterations must be a positive integer, got: $max_iterations"
    exit 1
fi

build_prompt() {
    local target="$1"
    cat <<EOF
/clean-code ${target}

IMPORTANT AUTOMATION OVERRIDES:

1. SKIP PHASE 5 (Approval): Do NOT ask which findings to fix. Automatically select ALL findings (HIGH, MEDIUM, and LOW) and proceed directly to Phase 6 (Incremental Application). Treat this as if the user responded "all" to the approval prompt.

2. TERMINATION SIGNAL: If Phase 4 determines there are zero findings (the module passes Clean Code analysis), you MUST output the following marker on its own line exactly as shown:

$PASS_MARKER

Output this marker AFTER the standard "Clean Code Analysis: PASS" message. This marker is used by the calling script to detect that the module is clean.

3. FINDINGS SIGNAL: If Phase 4 produces findings and you proceed to fix them, output the following marker on its own line after all fixes are applied:

$FIXED_MARKER

4. Do NOT commit any changes. Leave all modifications uncommitted.
EOF
}

output_file=$(mktemp)
trap 'rm -f "$output_file"; exit 130' INT
trap 'rm -f "$output_file"' EXIT

report_clean() {
    echo ""
    elapsed=$(( $(date +%s) - start_time ))
    log_success "=== MODULE CLEAN ==="
    log_success "Target: $module_path"
    log_success "Achieved in $iteration iteration(s)"
    log_info "Total time: ${elapsed}s"
    log_warning "Changes are uncommitted. Review and commit when ready."
    exit 0
}

iteration=0
start_time=$(date +%s)

log_header "=== Ralph Clean: $module_path ==="
log_info "Max iterations: $max_iterations"

while [[ $iteration -lt $max_iterations ]]; do
    iteration=$((iteration + 1))

    log_header "=== Iteration $iteration/$max_iterations ==="

    prompt=$(build_prompt "$module_path")
    : > "$output_file"

    while IFS= read -r line; do
        if text=$(echo "$line" | jq -r '.message.content[]? | select(.type == "text") | .text' 2>/dev/null); then
            if [[ -n "$text" ]]; then
                printf '%s\n' "$text"
                printf '%s\n' "$text" >> "$output_file"
            fi
        else
            echo "$line"
        fi
    done < <(claude -p --permission-mode acceptEdits --output-format stream-json --verbose "$prompt" 2>&1)
    echo ""

    if grep -q "$PASS_MARKER" "$output_file"; then
        report_clean
    fi

    if grep -q "$NATIVE_PASS" "$output_file"; then
        report_clean
    fi

    if grep -q "$FIXED_MARKER" "$output_file"; then
        log_info "Fixes applied. Continuing to next iteration..."
        continue
    fi

    log_warning "No explicit marker detected. Assuming fixes were applied. Continuing..."
done

echo ""
elapsed=$(( $(date +%s) - start_time ))
log_error "=== MAX ITERATIONS REACHED ==="
log_error "Stopped after $max_iterations iterations."
log_warning "Target: $module_path"
log_info "Total time: ${elapsed}s"
log_warning "The module may still have Clean Code violations."
log_warning "Changes are uncommitted. Review and commit when ready."
exit 2

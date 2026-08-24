#!/usr/bin/env bash
# Test harness for scripts/pr/quality_gate.sh --staged.
# Plain bash, same shape as test_pre_pr_check.sh (bats not available).
#
# The gate calls a model, so these tests do not run a full analysis pass. They
# cover the parts that decide whether the gate evaluates anything at all, plus
# the three defects that made the checks unable to report:
#
#   1. checks 1 and 2 looped over a pipe, so their subshell threw away exit_code
#      and the warnings array - neither check could fail the gate
#   2. `grep -c ... || echo 0` produced "0\n0" and killed the arithmetic test
#      in check 3 under set -e
#   3. the complexity pattern matched score 8, which the documented budget allows

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$REPO_ROOT/scripts/pr/quality_gate.sh"
HELPER="$REPO_ROOT/scripts/pr/lib/llm_prompt.py"

PASS=0
FAIL=0

run_test() {
  local name="$1"
  shift
  if "$@" 2>&1; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name"
    FAIL=$((FAIL + 1))
  fi
}

# --- Test: no backend reachable is reported as skipped, not passed ---
test_unreachable_backend_exits_3() {
  local out code
  out=$(cd "$REPO_ROOT" && MCP_QUALITY_LLM_URL="http://127.0.0.1:1/v1" bash "$GATE" --staged 2>&1)
  code=$?
  [ "$code" -eq 3 ] || { echo "   expected exit 3, got $code"; return 1; }
  [[ "$out" == *"Skipped, NOT passed"* ]] || { echo "   skip message missing: $out"; return 1; }
}

# --- Test: staged mode does not require forge access ---
test_staged_mode_needs_no_gh() {
  grep -q 'MODE" = "pr" \] && ! command -v gh' "$GATE" \
    || { echo "   the gh requirement is not scoped to PR mode"; return 1; }
  grep -q 'git diff --cached --name-only' "$GATE" \
    || { echo "   staged mode does not read the index"; return 1; }
}

# --- Test: the analysis loops are not piped, so their results escape ---
test_loops_use_process_substitution() {
  local piped
  piped=$(grep -c 'echo "\$changed_files" | while' "$GATE" || true)
  [ "$piped" -eq 0 ] || { echo "   $piped analysis loop(s) still read from a pipe"; return 1; }
  local substituted
  substituted=$(grep -c 'done < <(echo "\$changed_files")' "$GATE" || true)
  [ "$substituted" -eq 2 ] || { echo "   expected 2 process-substitution loops, found $substituted"; return 1; }
}

# --- Test: check 3 counts files without the "0\n0" fallback ---
test_file_counts_use_grep_exit_only() {
  grep -qF "grep -Ec '^tests/.*\.(py|sh)\$' || true" "$GATE" \
    || { echo "   test-file count is not the grep -Ec form over py and sh"; return 1; }
  ! grep -q 'grep -c .* || echo "0"' "$GATE" \
    || { echo "   an '|| echo 0' fallback remains and yields two lines"; return 1; }
}

# --- Test: complexity 8 is within budget and must not be flagged ---
test_complexity_threshold_allows_8() {
  grep -qF 'grep -qi "score 9\|score 10"' "$GATE" \
    || { echo "   complexity pattern does not match only 9 and 10"; return 1; }
}

# --- Test: the helper reports an unusable endpoint as no-backend, not as a reply ---
test_helper_signals_no_backend() {
  local code
  echo "ping" | MCP_QUALITY_LLM_URL="http://127.0.0.1:1/v1" python3 "$HELPER" >/dev/null 2>&1
  code=$?
  [ "$code" -eq 3 ] || { echo "   expected exit 3 from the helper, got $code"; return 1; }
}

# --- Test: a pyscn that never ran is not summarised as OK ---
test_pyscn_skip_not_reported_as_ok() {
  grep -q 'pyscn_ran=true' "$GATE" \
    || { echo "   pyscn run is not tracked"; return 1; }
  grep -q 'pyscn analysis: SKIPPED (pyscn not installed)' "$GATE" \
    || { echo "   a skipped pyscn analysis has no distinct summary line"; return 1; }
  awk '/if \[ "\$pyscn_ran" = true \]; then/{found=1} END{exit !found}' "$GATE" \
    || { echo "   the summary still keys off RUN_PYSCN rather than pyscn_ran"; return 1; }
}

run_test "unreachable backend exits 3, not 0" test_unreachable_backend_exits_3
run_test "staged mode needs no gh" test_staged_mode_needs_no_gh
run_test "analysis loops use process substitution" test_loops_use_process_substitution
run_test "file counts rely on grep's own output" test_file_counts_use_grep_exit_only
run_test "complexity threshold allows a score of 8" test_complexity_threshold_allows_8
run_test "helper exits 3 when the endpoint is unusable" test_helper_signals_no_backend
run_test "skipped pyscn is not summarised as OK" test_pyscn_skip_not_reported_as_ok

echo ""
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]

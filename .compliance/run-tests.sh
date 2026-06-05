#!/usr/bin/env bash
#
# Negative-test harness for the .compliance/ checkers.
#
# Without this, refactoring a checker that breaks its detection silently
# passes -- the rules digest catches "rule set changed" but not "rule
# set is broken." Each fixture under __tests__/<rule>/{should-fail,should-pass}/<name>/
# contains a self-contained `src/` and `allowlist/` directory; we point
# the checker at them via env vars and assert the expected exit code.
#
# Layout per fixture:
#   .compliance/__tests__/<rule>/<expected>/<name>/
#     src/                       <- checker treats this as repo `src/`
#       *.js                     <- fixture source files
#     allowlist/                 <- checker reads its JSON allowlists from here
#       <rule>-allowlist.json    OR forbidden-imports.json, etc.
#
# The harness:
#   - For each fixture, sets COMPLIANCE_REPO_OVERRIDE=<fixture> (so
#     checker walks <fixture>/src/) and COMPLIANCE_ALLOWLIST_DIR=<fixture>/allowlist.
#   - Runs the matching checker.
#   - Asserts exit==0 for should-pass, exit!=0 for should-fail.
#
# Output: one line per fixture, summary at end. Exits non-zero on any
# unexpected outcome.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="${SCRIPT_DIR}/__tests__"

checker_for_rule() {
  case "$1" in
    check-routes)  echo "check-routes.mjs" ;;
    check-secrets) echo "check-secrets.mjs" ;;
    check-imports) echo "check-imports.mjs" ;;
    *)             echo "" ;;
  esac
}

PASS=0
FAIL=0
FAILED_NAMES=()

run_fixture() {
  local rule="$1"
  local expected="$2"
  local fixture_dir="$3"
  local name
  name="$(basename "${fixture_dir}")"

  local checker
  checker="$(checker_for_rule "${rule}")"
  if [[ -z "${checker}" ]]; then
    echo "  [${rule}/${expected}/${name}] SKIPPED (no checker mapping)"
    return
  fi

  COMPLIANCE_REPO_OVERRIDE="${fixture_dir}" \
  COMPLIANCE_ALLOWLIST_DIR="${fixture_dir}/allowlist" \
    node "${SCRIPT_DIR}/${checker}" >/dev/null 2>&1
  local rc=$?

  local ok=false
  if [[ "${expected}" == "should-pass" && ${rc} -eq 0 ]]; then ok=true; fi
  if [[ "${expected}" == "should-fail" && ${rc} -ne 0 ]]; then ok=true; fi

  if [[ "${ok}" == "true" ]]; then
    echo "  [PASS] ${rule}/${expected}/${name} (rc=${rc})"
    PASS=$((PASS+1))
  else
    echo "  [FAIL] ${rule}/${expected}/${name} (rc=${rc}, expected ${expected})"
    FAIL=$((FAIL+1))
    FAILED_NAMES+=("${rule}/${expected}/${name}")
  fi
}

if [[ ! -d "${TESTS_DIR}" ]]; then
  echo "[checker-self-tests] no __tests__/ directory; skipping" >&2
  exit 0
fi

echo "[checker-self-tests] running fixtures under ${TESTS_DIR}"

for rule_dir in "${TESTS_DIR}"/*/; do
  rule="$(basename "${rule_dir}")"
  for expected in should-pass should-fail; do
    [[ -d "${rule_dir}${expected}" ]] || continue
    for fixture_dir in "${rule_dir}${expected}"/*/; do
      [[ -d "${fixture_dir}" ]] || continue
      # strip trailing slash for cleaner display
      run_fixture "${rule}" "${expected}" "${fixture_dir%/}"
    done
  done
done

echo ""
echo "[checker-self-tests] ${PASS} passed, ${FAIL} failed"

if [[ ${FAIL} -gt 0 ]]; then
  printf '  failed: %s\n' "${FAILED_NAMES[@]}"
  exit 1
fi
exit 0

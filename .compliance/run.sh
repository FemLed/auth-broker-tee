#!/usr/bin/env bash
#
# Compliance suite for auth-broker-tee.
#
# Runs every check that gates a build. Each check writes its JSON result to
# .compliance-results/<name>.json on stdout (success or failure -- the JSON is
# always preserved). Human-readable error context goes to stderr.
#
# The orchestrator aggregates per-check results into summary.json and exits
# non-zero if any check failed. The aggregated summary plus the rules digest
# (sha256 over .compliance/) is what the GitHub Actions workflow embeds into
# the in-toto attestation predicate signed in Sigstore.
#
# Tools expected on PATH (the GHA workflow installs each):
#   - node       (>= 20, for the .mjs checkers)
#   - semgrep    (Python, pinned in workflow)
#   - syft       (SBOM generator)
#   - osv-scanner (vulnerability scanner)
#   - jq, sha256sum, find, sort
#
# Anything not installed is logged as "skipped" -- this matters only for local
# dev. The GHA workflow runs in --strict mode which fails on any skip.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${RESULTS_DIR:-${REPO_ROOT}/.compliance-results}"

STRICT="${STRICT:-false}"

mkdir -p "${RESULTS_DIR}"
rm -f "${RESULTS_DIR}"/*.json "${RESULTS_DIR}"/*.spdx.json 2>/dev/null || true

# ---------------------------------------------------------------------------
# Compute the rules digest. This is sha256 over the canonicalized contents
# of .compliance/, excluding human-readable artifacts (*.md). Verifiers pin
# this digest so that any weakening of the rules is detectable.
# ---------------------------------------------------------------------------
RULES_DIGEST="sha256:$(
  find "${SCRIPT_DIR}" -type f \
    \( -name '*.sh' -o -name '*.mjs' -o -name '*.yml' -o -name '*.json' -o -name '*.js' \) \
    -not -path '*/node_modules/*' \
    | sort \
    | xargs cat \
    | sha256sum \
    | cut -d' ' -f1
)"

echo "[compliance] rules digest: ${RULES_DIGEST}" >&2

OVERALL_STATUS="passed"
FAILURES=()
SKIPS=()

run_check() {
  local name="$1"; shift
  local outfile="${RESULTS_DIR}/${name}.json"
  echo "" >&2
  echo "[compliance] ${name}..." >&2
  if "$@" > "${outfile}"; then
    echo "[compliance] ${name}: PASSED" >&2
  else
    local rc=$?
    echo "[compliance] ${name}: FAILED (rc=${rc})" >&2
    OVERALL_STATUS="failed"
    FAILURES+=("${name}")
  fi
}

skip_check() {
  local name="$1"
  local reason="$2"
  local outfile="${RESULTS_DIR}/${name}.json"
  echo "[compliance] ${name}: SKIPPED (${reason})" >&2
  printf '{"status":"skipped","reason":%s}\n' "$(printf '%s' "${reason}" | jq -Rs .)" > "${outfile}"
  SKIPS+=("${name}")
  if [[ "${STRICT}" == "true" ]]; then
    OVERALL_STATUS="failed"
    FAILURES+=("${name} (skipped under STRICT)")
  fi
}

# ---------------------------------------------------------------------------
# 1. Semgrep — pattern-based static analysis on src/
# ---------------------------------------------------------------------------
if command -v semgrep >/dev/null 2>&1; then
  if semgrep --config "${SCRIPT_DIR}/semgrep.yml" \
             --json --quiet --error \
             "${REPO_ROOT}/src" \
             > "${RESULTS_DIR}/semgrep-raw.json" 2>"${RESULTS_DIR}/semgrep.stderr"; then
    # Normalize: the verifier and predicate consumers expect every entry
    # in `results.*` to carry an explicit `status: passed|failed|skipped`.
    jq --arg status "passed" '. + {status: $status}' "${RESULTS_DIR}/semgrep-raw.json" > "${RESULTS_DIR}/semgrep.json"
    echo "[compliance] semgrep: PASSED" >&2
  else
    jq --arg status "failed" '. + {status: $status}' "${RESULTS_DIR}/semgrep-raw.json" > "${RESULTS_DIR}/semgrep.json" 2>/dev/null \
      || jq -n --arg status "failed" '{status: $status}' > "${RESULTS_DIR}/semgrep.json"
    echo "[compliance] semgrep: FAILED" >&2
    cat "${RESULTS_DIR}/semgrep.stderr" >&2 || true
    OVERALL_STATUS="failed"
    FAILURES+=("semgrep")
  fi
else
  skip_check semgrep "semgrep CLI not installed"
fi

# ---------------------------------------------------------------------------
# 2. Custom AST checks (require Node + acorn installed in .compliance/)
# ---------------------------------------------------------------------------
if [[ ! -d "${SCRIPT_DIR}/node_modules" ]]; then
  echo "[compliance] installing .compliance/ dependencies..." >&2
  ( cd "${SCRIPT_DIR}" && npm ci --prefer-offline --no-audit --no-fund --ignore-scripts --loglevel=error )
fi

run_check check-routes  node "${SCRIPT_DIR}/check-routes.mjs"
run_check check-secrets node "${SCRIPT_DIR}/check-secrets.mjs"
run_check check-imports node "${SCRIPT_DIR}/check-imports.mjs"
run_check check-route-integrity node "${SCRIPT_DIR}/check-route-integrity.mjs"

# ---------------------------------------------------------------------------
# 2b. Negative-test harness: verifies the checkers themselves still detect
#     the bypass paths they were written to detect. Without this, a
#     refactor that breaks a checker would silently pass production CI.
# ---------------------------------------------------------------------------
if [[ -d "${SCRIPT_DIR}/__tests__" ]]; then
  TEST_LOG="${RESULTS_DIR}/checker-self-tests.log"
  if bash "${SCRIPT_DIR}/run-tests.sh" > "${TEST_LOG}" 2>&1; then
    PASS_COUNT=$(grep -c '^  \[PASS\]' "${TEST_LOG}" || echo 0)
    jq -n --arg status "passed" --argjson pass_count "${PASS_COUNT}" --arg log_path ".compliance-results/checker-self-tests.log" \
      '{status: $status, pass_count: $pass_count, log_path: $log_path}' \
      > "${RESULTS_DIR}/checker-self-tests.json"
    echo "[compliance] checker-self-tests: PASSED (${PASS_COUNT} fixtures)" >&2
  else
    cat "${TEST_LOG}" >&2 || true
    jq -n --arg status "failed" --arg log_path ".compliance-results/checker-self-tests.log" \
      '{status: $status, log_path: $log_path}' \
      > "${RESULTS_DIR}/checker-self-tests.json"
    echo "[compliance] checker-self-tests: FAILED" >&2
    OVERALL_STATUS="failed"
    FAILURES+=("checker-self-tests")
  fi
else
  skip_check checker-self-tests ".compliance/__tests__/ directory not present"
fi

# ---------------------------------------------------------------------------
# 3. Branch protection assertion (only meaningful with a GITHUB_TOKEN)
# ---------------------------------------------------------------------------
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  run_check branch-protection node "${SCRIPT_DIR}/branch-protection.mjs"
else
  skip_check branch-protection "GITHUB_TOKEN not set (local dev)"
fi

# ---------------------------------------------------------------------------
# 4. SBOM via Syft
# ---------------------------------------------------------------------------
if command -v syft >/dev/null 2>&1; then
  SBOM_PATH="${RESULTS_DIR}/sbom.spdx.json"
  if syft "dir:${REPO_ROOT}" \
          --exclude '**/.compliance/**' \
          --exclude '**/.compliance-results/**' \
          --exclude '**/verifier/**' \
          --exclude '**/terraform/**' \
          -o "spdx-json=${SBOM_PATH}" \
          --quiet 2>"${RESULTS_DIR}/sbom.stderr"; then
    SBOM_DIGEST="sha256:$(sha256sum "${SBOM_PATH}" | cut -d' ' -f1)"
    PACKAGE_COUNT=$(jq '.packages | length' "${SBOM_PATH}")
    jq -n \
      --arg status "passed" \
      --arg sbom_digest "${SBOM_DIGEST}" \
      --arg sbom_path "${SBOM_PATH}" \
      --argjson package_count "${PACKAGE_COUNT}" \
      '{status: $status, sbom_digest: $sbom_digest, sbom_path: $sbom_path, package_count: $package_count}' \
      > "${RESULTS_DIR}/sbom.json"
    echo "[compliance] sbom: PASSED (${PACKAGE_COUNT} packages, digest ${SBOM_DIGEST})" >&2
  else
    echo "[compliance] sbom: FAILED" >&2
    cat "${RESULTS_DIR}/sbom.stderr" >&2 || true
    jq -n --arg status "failed" '{status: $status}' > "${RESULTS_DIR}/sbom.json"
    OVERALL_STATUS="failed"
    FAILURES+=("sbom")
  fi
else
  skip_check sbom "syft not installed"
fi

# ---------------------------------------------------------------------------
# 5. OSV-Scanner against the SBOM. Fails on any HIGH/CRITICAL CVE.
# ---------------------------------------------------------------------------
if command -v osv-scanner >/dev/null 2>&1 && [[ -f "${RESULTS_DIR}/sbom.spdx.json" ]]; then
  # OSV-Scanner exits 1 when ANY vuln found (even informational). We want to
  # fail only on HIGH/CRITICAL, so we always capture output and parse severity
  # ourselves. We must NOT swallow failures here -- a missing or unparseable
  # vuln-raw.json should be a failure, not a silent zero.
  set +e
  osv-scanner --format=json --sbom="${RESULTS_DIR}/sbom.spdx.json" \
    > "${RESULTS_DIR}/vuln-raw.json" 2>"${RESULTS_DIR}/vuln.stderr"
  OSV_RC=$?
  set -e

  if [[ ! -s "${RESULTS_DIR}/vuln-raw.json" ]]; then
    echo "[compliance] vuln-scan: FAILED (osv-scanner produced empty output, rc=${OSV_RC})" >&2
    cat "${RESULTS_DIR}/vuln.stderr" >&2 || true
    jq -n --arg status "failed" --arg reason "osv-scanner produced no output" '{status: $status, reason: $reason}' > "${RESULTS_DIR}/vuln.json"
    OVERALL_STATUS="failed"
    FAILURES+=("vuln-scan")
  elif ! jq empty "${RESULTS_DIR}/vuln-raw.json" >/dev/null 2>&1; then
    echo "[compliance] vuln-scan: FAILED (osv-scanner output was not valid JSON, rc=${OSV_RC})" >&2
    cat "${RESULTS_DIR}/vuln.stderr" >&2 || true
    jq -n --arg status "failed" --arg reason "osv-scanner output was not valid JSON" '{status: $status, reason: $reason}' > "${RESULTS_DIR}/vuln.json"
    OVERALL_STATUS="failed"
    FAILURES+=("vuln-scan")
  else

  # Severity may appear as either a label (e.g. database_specific.severity
  # = "HIGH"/"CRITICAL"/"MODERATE") or a CVSS vector in severity[].score.
  # We count a vuln as HIGH if EITHER:
  #   - the label matches HIGH/CRITICAL (case-insensitive), or
  #   - the CVSS vector contains a high impact in any dimension (C:H, I:H,
  #     or A:H), which is a defensible "this can hurt us" approximation
  #     without doing full CVSS base-score arithmetic in jq.
  # The heuristic intentionally prefers false positives (failed builds)
  # over false negatives (silent passes).
  HIGH_COUNT=$(
    jq '
      [
        .results[]?.packages[]?.vulnerabilities[]?
        | select(
            (
              (.database_specific.severity? // "" | ascii_upcase | test("HIGH|CRITICAL"))
            )
            or
            (
              [.severity[]? | (.score // "") | ascii_upcase
                | test("HIGH|CRITICAL|/C:H|/I:H|/A:H")
              ] | any
            )
          )
      ] | length' "${RESULTS_DIR}/vuln-raw.json"
  )
  if [[ -z "${HIGH_COUNT}" ]] || ! [[ "${HIGH_COUNT}" =~ ^[0-9]+$ ]]; then
    echo "[compliance] vuln-scan: FAILED (could not parse severity from vuln-raw.json)" >&2
    jq -n --arg status "failed" --arg reason "severity parse failed" '{status: $status, reason: $reason}' > "${RESULTS_DIR}/vuln.json"
    OVERALL_STATUS="failed"
    FAILURES+=("vuln-scan")
    HIGH_COUNT=0
  fi
  TOTAL_COUNT=$(
    jq '[.results[]?.packages[]?.vulnerabilities[]?] | length' \
      "${RESULTS_DIR}/vuln-raw.json"
  )
  if [[ "${HIGH_COUNT}" -gt 0 ]]; then
    jq -n \
      --arg status "failed" \
      --argjson high_count "${HIGH_COUNT}" \
      --argjson total_count "${TOTAL_COUNT}" \
      '{status: $status, high_count: $high_count, total_count: $total_count, raw_path: ".compliance-results/vuln-raw.json"}' \
      > "${RESULTS_DIR}/vuln.json"
    echo "[compliance] vuln-scan: FAILED (${HIGH_COUNT} HIGH/CRITICAL, ${TOTAL_COUNT} total)" >&2
    OVERALL_STATUS="failed"
    FAILURES+=("vuln-scan")
  else
    jq -n \
      --arg status "passed" \
      --argjson high_count "${HIGH_COUNT}" \
      --argjson total_count "${TOTAL_COUNT}" \
      '{status: $status, high_count: $high_count, total_count: $total_count}' \
      > "${RESULTS_DIR}/vuln.json"
    echo "[compliance] vuln-scan: PASSED (${TOTAL_COUNT} non-high advisories)" >&2
  fi
  fi  # close: empty vuln-raw.json branch
else
  # Note: file name must match what the aggregator reads (vuln.json),
  # not the human-readable check name (vuln-scan).
  skip_check vuln "osv-scanner not installed or SBOM missing"
fi

# ---------------------------------------------------------------------------
# Aggregate into summary.json — this is what the workflow signs as the
# in-toto compliance predicate.
# ---------------------------------------------------------------------------
SUMMARY="${RESULTS_DIR}/summary.json"

if [[ ${#FAILURES[@]} -eq 0 ]]; then FAILURES_JSON='[]'; else
  FAILURES_JSON=$(printf '%s\n' "${FAILURES[@]}" | jq -R . | jq -s .)
fi
if [[ ${#SKIPS[@]} -eq 0 ]]; then SKIPS_JSON='[]'; else
  SKIPS_JSON=$(printf '%s\n' "${SKIPS[@]}" | jq -R . | jq -s .)
fi

read_or_null() {
  local f="$1"
  if [[ -s "${f}" ]]; then jq '.' "${f}"; else echo 'null'; fi
}

jq -n \
  --arg overall_status "${OVERALL_STATUS}" \
  --arg compliance_rules_digest "${RULES_DIGEST}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg commit_sha "${GITHUB_SHA:-${COMMIT_SHA:-unknown}}" \
  --arg ref "${GITHUB_REF:-${GIT_REF:-unknown}}" \
  --arg workflow_ref "${GITHUB_WORKFLOW_REF:-unknown}" \
  --argjson semgrep "$(read_or_null "${RESULTS_DIR}/semgrep.json")" \
  --argjson check_routes "$(read_or_null "${RESULTS_DIR}/check-routes.json")" \
  --argjson check_secrets "$(read_or_null "${RESULTS_DIR}/check-secrets.json")" \
  --argjson check_imports "$(read_or_null "${RESULTS_DIR}/check-imports.json")" \
  --argjson check_route_integrity "$(read_or_null "${RESULTS_DIR}/check-route-integrity.json")" \
  --argjson checker_self_tests "$(read_or_null "${RESULTS_DIR}/checker-self-tests.json")" \
  --argjson branch_protection "$(read_or_null "${RESULTS_DIR}/branch-protection.json")" \
  --argjson sbom "$(read_or_null "${RESULTS_DIR}/sbom.json")" \
  --argjson vuln_scan "$(read_or_null "${RESULTS_DIR}/vuln.json")" \
  --argjson failures "${FAILURES_JSON}" \
  --argjson skips "${SKIPS_JSON}" \
  '{
    overall_status: $overall_status,
    compliance_rules_digest: $compliance_rules_digest,
    generated_at: $generated_at,
    commit_sha: $commit_sha,
    ref: $ref,
    workflow_ref: $workflow_ref,
    failures: $failures,
    skips: $skips,
    results: {
      semgrep: $semgrep,
      check_routes: $check_routes,
      check_secrets: $check_secrets,
      check_imports: $check_imports,
      check_route_integrity: $check_route_integrity,
      checker_self_tests: $checker_self_tests,
      branch_protection: $branch_protection,
      sbom: $sbom,
      vuln_scan: $vuln_scan
    }
  }' > "${SUMMARY}"

echo "" >&2
echo "[compliance] summary: ${SUMMARY}" >&2
echo "[compliance] OVERALL: ${OVERALL_STATUS}" >&2

if [[ "${OVERALL_STATUS}" != "passed" ]]; then
  exit 1
fi

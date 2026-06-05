#!/usr/bin/env node
/**
 * branch-protection.mjs
 *
 * Calls the GitHub API to fetch branch-protection settings for the branch
 * being built (default `master`). Asserts the policies that protect the
 * supply chain:
 *
 *   - required_signatures.enabled == true
 *   - allow_force_pushes.enabled == false
 *   - allow_deletions.enabled == false
 *   - enforce_admins.enabled == true (admin-bypass disabled)
 *   - required_status_checks includes the build-and-attest compliance gate
 *   - required_status_checks includes the TEE First Principles gate
 *
 * The result -- whether passed or failed -- is included in the in-toto
 * compliance predicate so that verifiers can detect regressions in
 * branch protection over time even on builds that were grandfathered.
 *
 * Required env:
 *   GITHUB_TOKEN     (provided automatically in GHA workflows)
 *   GITHUB_REPOSITORY (e.g. "FemLed/auth-broker-tee", set by GHA)
 *
 * Optional env:
 *   PROTECTED_BRANCH (default "master")
 *
 * In a local-dev shell where GITHUB_TOKEN is not set, the orchestrator
 * skips this check entirely.
 *
 * Note: the workflow GITHUB_TOKEN can read the public branch metadata
 * endpoint, which exposes `protected` and required status checks, but it
 * may not be able to read the admin-only branch-protection endpoint. In
 * that case this checker still enforces the load-bearing required CI
 * context and records a warning that admin-only fields were not visible.
 */
const TOKEN = process.env.GITHUB_TOKEN;
const REPO = process.env.GITHUB_REPOSITORY;
const BRANCH = process.env.PROTECTED_BRANCH || "master";
const REQUIRED_STATUS_PATTERNS = [
  /^build-and-attest(?: \/ .*)?$/i,
  /^build-and-attest \/ compliance gate$/i,
  /^compliance gate$/i,
];
const REQUIRED_TEE_STATUS_PATTERNS = [
  /^build-and-attest \/ tee-first-principles-review$/i,
  /^tee-first-principles-review$/i,
];

function emit(status, fields = {}) {
  process.stdout.write(JSON.stringify({ status, branch: BRANCH, ...fields }, null, 2) + "\n");
  process.exit(status === "passed" ? 0 : 1);
}

if (!TOKEN) emit("failed", { error: "GITHUB_TOKEN not set" });
if (!REPO || !REPO.includes("/")) emit("failed", { error: "GITHUB_REPOSITORY env var missing or malformed" });

async function getJson(url) {
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "femled-auth-broker-compliance",
    },
  });
  const body = await response.text();
  let json = null;
  try { json = body ? JSON.parse(body) : null; } catch { /* handled by caller */ }
  return { response, body, json };
}

const branchURL = `https://api.github.com/repos/${REPO}/branches/${BRANCH}`;
const protectionURL = `${branchURL}/protection`;

let branchResp;
try {
  branchResp = await getJson(branchURL);
} catch (err) {
  emit("failed", { error: `GitHub branch API request failed: ${err.message}` });
}
if (!branchResp.response.ok || !branchResp.json) {
  emit("failed", {
    error: `GitHub branch API returned ${branchResp.response.status}`,
    response_body: branchResp.body.slice(0, 1000),
  });
}

let protectionResp = null;
try {
  protectionResp = await getJson(protectionURL);
} catch {
  protectionResp = null;
}

const protectionVisible = Boolean(protectionResp?.response?.ok && protectionResp.json);
const data = protectionVisible ? protectionResp.json : {};

const requiredStatusChecks = (
  data.required_status_checks?.contexts ||
  data.required_status_checks?.checks?.map((c) => c.context) ||
  branchResp.json.protection?.required_status_checks?.contexts ||
  branchResp.json.protection?.required_status_checks?.checks?.map((c) => c.context) ||
  []
);
const hasRequiredComplianceGate = requiredStatusChecks.some((check) =>
  REQUIRED_STATUS_PATTERNS.some((pattern) => pattern.test(check))
);
const hasRequiredTeeFirstPrinciplesGate = requiredStatusChecks.some((check) =>
  REQUIRED_TEE_STATUS_PATTERNS.some((pattern) => pattern.test(check))
);
const findings = {
  branch_protected: branchResp.json.protected === true,
  admin_protection_details_visible: protectionVisible === true,
  signed_commits_required: protectionVisible ? data.required_signatures?.enabled === true : null,
  force_pushes_allowed: protectionVisible ? data.allow_force_pushes?.enabled === true : null,
  deletions_allowed: protectionVisible ? data.allow_deletions?.enabled === true : null,
  admin_bypass_enforced: protectionVisible ? data.enforce_admins?.enabled === true : null,
  required_status_checks: requiredStatusChecks,
  compliance_gate_required: hasRequiredComplianceGate,
  tee_first_principles_gate_required: hasRequiredTeeFirstPrinciplesGate,
  require_linear_history: protectionVisible ? data.required_linear_history?.enabled === true : null,
  block_creations_when_branch_doesnt_exist: protectionVisible ? data.block_creations?.enabled === true : null,
};

const failures = [];
const warnings = [];
if (!findings.branch_protected) failures.push("branch must be protected");
if (protectionVisible) {
  if (!findings.signed_commits_required) failures.push("required_signatures must be enabled");
  if (findings.force_pushes_allowed) failures.push("allow_force_pushes must be false");
  if (findings.deletions_allowed) failures.push("allow_deletions must be false");
  if (!findings.admin_bypass_enforced) failures.push("enforce_admins must be true (admin bypass disabled)");
} else {
  warnings.push("admin-only branch protection details were not visible to this token; required CI gate was checked via public branch metadata");
}
if (!findings.compliance_gate_required) {
  failures.push("required_status_checks must include the build-and-attest compliance gate");
}
if (!findings.tee_first_principles_gate_required) {
  failures.push("required_status_checks must include the TEE First Principles gate");
}

if (failures.length > 0) {
  emit("failed", {
    error: "branch protection policy is too permissive",
    failures,
    warnings,
    findings,
    remediation: `Visit https://github.com/${REPO}/settings/branches and tighten the protection rule for '${BRANCH}'.`,
  });
}

emit("passed", { findings, warnings });

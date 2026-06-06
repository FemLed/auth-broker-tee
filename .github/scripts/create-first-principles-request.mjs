#!/usr/bin/env node
// Build a first-principles adjudication request for a change to auth-broker-tee.
//
// The caller only PROPOSES a commit SHA (plus CI-produced compliance digests).
// It deliberately does NOT send a diff or changed-file list: the active TEE pulls
// the proposed change DIRECTLY FROM GITHUB at the OIDC-bound commit using the
// FemLed GitHub App installation token it mints in-process, so the reviewed bytes
// are GitHub's source of truth, never operator-submitted input.
import crypto from "node:crypto";
import fs from "node:fs";
import { execFileSync } from "node:child_process";

const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));
const eventName = process.env.GITHUB_EVENT_NAME;
const repository = process.env.GITHUB_REPOSITORY;
const isPullRequestEvent = eventName === "pull_request" || eventName === "pull_request_target";
const headSha = isPullRequestEvent
  ? event.pull_request.head.sha
  : process.env.GITHUB_SHA;
let baseSha = isPullRequestEvent
  ? event.pull_request.base.sha
  : event.before;

// baseSha is only the compare base the TEE diffs against; it is metadata, not the
// reviewed content. The TEE re-fetches and diffs both commits from GitHub itself.
if (!baseSha || /^0{40}$/.test(baseSha)) {
  baseSha = resolveParentSha(headSha);
}

const summaryPath = ".compliance-results/summary.json";
const complianceSummary = fs.existsSync(summaryPath)
  ? fs.readFileSync(summaryPath, "utf8")
  : "{}";
let complianceRulesDigest = null;
try {
  complianceRulesDigest = JSON.parse(complianceSummary).compliance_rules_digest || null;
} catch {
  complianceRulesDigest = null;
}

const request = {
  repository,
  eventName,
  pullNumber: event.pull_request?.number || null,
  baseSha: /^[a-f0-9]{40}$/i.test(baseSha || "") ? baseSha : null,
  headSha,
  complianceSummaryDigest: sha256Digest(complianceSummary),
  complianceRulesDigest,
  workflowRunId: process.env.GITHUB_RUN_ID,
  workflowRunUrl: `${process.env.GITHUB_SERVER_URL}/${repository}/actions/runs/${process.env.GITHUB_RUN_ID}`,
  nonce: crypto.randomBytes(32).toString("base64url"),
};

const out = process.argv[2] || "first-principles-request.json";
fs.writeFileSync(out, `${JSON.stringify(request, null, 2)}\n`);

function resolveParentSha(sha) {
  try {
    return execFileSync("git", ["rev-parse", `${sha}^`], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

function sha256Digest(input) {
  return `sha256:${crypto.createHash("sha256").update(input).digest("hex")}`;
}

#!/usr/bin/env node
// Build a first-principles adjudication request for a change to auth-broker-tee.
//
// TRANSITIONAL DUAL-MODE COMPAT -- remove right after the reviewer roll.
//
// This request carries BOTH the proposed commit SHA and a caller-supplied
// `diff` + `changedFiles`:
//
// - The currently DEPLOYED legacy reviewer (the pre-#1 image that must approve
//   this repo's changes today) rejects any request without a non-empty `diff`
//   and `changedFiles`; it reviews the caller-supplied diff and echoes its
//   digests back inside the attested payload.
// - The post-#5 reviewer ignores caller-supplied diff fields entirely: it pulls
//   the proposed change DIRECTLY FROM GITHUB at the OIDC-bound commit using the
//   FemLed GitHub App installation token it mints in-process, so the reviewed
//   bytes are GitHub's source of truth, never operator-submitted input.
//
// Sending the diff is therefore required by the deployed reviewer and inert to
// its successor. Once the post-#5 image is the active TEE, drop the diff send
// and restore the propose-only request (and the strict no-caller-diff check in
// verify-first-principles-adjudication.mjs).
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
// reviewed content. The post-#5 TEE re-fetches and diffs both commits from GitHub
// itself; the legacy TEE reviews the diff computed below over the same range.
if (!baseSha || /^0{40}$/.test(baseSha)) {
  baseSha = resolveParentSha(headSha);
}

const range = `${baseSha || `${headSha}^`}...${headSha}`;
const { diff, changedFiles } = eventName === "pull_request_target"
  ? await fetchPullRequestDiff(event.pull_request.number)
  : readLocalDiff(range);

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
  changedFiles,
  diff,
  complianceSummary,
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
    return git(["rev-parse", `${sha}^`]).trim();
  } catch {
    return null;
  }
}

function git(args, maxBuffer) {
  return execFileSync("git", args, {
    encoding: "utf8",
    maxBuffer,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function sha256Digest(input) {
  return `sha256:${crypto.createHash("sha256").update(input).digest("hex")}`;
}

function readLocalDiff(range) {
  return {
    diff: git(["diff", "--unified=80", range], 900 * 1024) || "No textual diff was produced.",
    changedFiles: git(["diff", "--name-only", range], 256 * 1024)
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  };
}

async function fetchPullRequestDiff(pullNumber) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error("GITHUB_TOKEN is required for pull_request_target diff retrieval");
  }

  const headers = {
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "auth-broker-tee-first-principles",
  };

  const diffResponse = await fetch(`https://api.github.com/repos/${repository}/pulls/${pullNumber}`, {
    headers: {
      ...headers,
      Accept: "application/vnd.github.v3.diff",
    },
  });
  if (!diffResponse.ok) {
    throw new Error(`Failed to fetch PR diff: ${diffResponse.status}`);
  }
  const diff = await diffResponse.text();

  const changedFiles = [];
  for (let page = 1; page <= 10; page += 1) {
    const filesResponse = await fetch(
      `https://api.github.com/repos/${repository}/pulls/${pullNumber}/files?per_page=100&page=${page}`,
      {
        headers: {
          ...headers,
          Accept: "application/vnd.github+json",
        },
      }
    );
    if (!filesResponse.ok) {
      throw new Error(`Failed to fetch PR files: ${filesResponse.status}`);
    }
    const files = await filesResponse.json();
    changedFiles.push(...files.map((file) => file.filename));
    if (files.length < 100) break;
  }

  return { diff, changedFiles };
}

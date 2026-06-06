#!/usr/bin/env node
// Build a first-principles adjudication request for a change to auth-broker-tee.
//
// Compatibility note: this sends the diff + changed files AS WELL AS the proposed
// commit SHA. The currently-deployed TEE still requires the caller-supplied diff;
// the successor TEE ignores it and re-fetches the change DIRECTLY FROM GITHUB at
// the OIDC-bound commit. Sending the diff is harmless to the successor TEE and
// keeps the deploy pipeline working across the rollover; once every slot runs the
// successor image, the diff send can be dropped.
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

if (!baseSha || /^0{40}$/.test(baseSha)) {
  baseSha = `${headSha}^`;
}

const range = `${baseSha}...${headSha}`;
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
  baseSha: /^[a-f0-9]{40}$/i.test(baseSha) ? baseSha : null,
  headSha,
  changedFiles,
  diff,
  complianceSummaryDigest: sha256Digest(complianceSummary),
  complianceRulesDigest,
  workflowRunId: process.env.GITHUB_RUN_ID,
  workflowRunUrl: `${process.env.GITHUB_SERVER_URL}/${repository}/actions/runs/${process.env.GITHUB_RUN_ID}`,
  nonce: crypto.randomBytes(32).toString("base64url"),
};

const out = process.argv[2] || "first-principles-request.json";
fs.writeFileSync(out, `${JSON.stringify(request, null, 2)}\n`);

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

import { test } from "node:test";
import assert from "node:assert/strict";
import { collectGitHubSourceEvidence } from "../src/github-source-evidence.js";

const COMMIT = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const getToken = async () => "ghs_faketoken";

function jsonResponse(body, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => body };
}

function githubFetch(routes) {
  return async (url) => {
    for (const [pattern, responder] of routes) {
      if (pattern.test(url)) return responder(url);
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
}

test("collects full contents of changed source files directly from GitHub", async () => {
  const fetchImpl = githubFetch([
    [/\/commits\/a1b2c3/, () => jsonResponse({ sha: COMMIT, commit: { tree: { sha: "t" } }, parents: [], files: [] })],
    [/\/compare\//, () => jsonResponse({ files: [
      { filename: "src/routes.js", status: "modified", patch: "@@ -1 +1 @@\n+scope", additions: 1, deletions: 0 },
    ] })],
    [/\/contents\/src\/routes\.js/, () => jsonResponse({ type: "file", encoding: "base64", content: Buffer.from("export const mint = () => 'scoped';\n").toString("base64") })],
  ]);
  const evidence = await collectGitHubSourceEvidence({ repoOwner: "FemLed", repoName: "auth-broker-tee", commitSha: COMMIT, baseSha: "b".repeat(40), getToken, fetchImpl });

  assert.equal(evidence.present, true);
  assert.deepEqual(evidence.changedFilePaths, ["src/routes.js"]);
  assert.ok(evidence.sourceFiles["src/routes.js"]);
  assert.equal(evidence.excludedPathCount, 0);
  assert.match(evidence.evidenceDigest, /^sha256:/);
});

test("excludes vendored deps / build artifacts (node_modules, .terraform, dist) from the review", async () => {
  const fetchImpl = githubFetch([
    [/\/commits\/a1b2c3/, () => jsonResponse({ sha: COMMIT, commit: { tree: { sha: "t" } }, parents: [], files: [] })],
    [/\/compare\//, () => jsonResponse({ files: [
      { filename: "src/routes.js", status: "modified", patch: "@@ -1 +1 @@\n+scope", additions: 1, deletions: 0 },
      { filename: "node_modules/jose/index.js", status: "modified", patch: "@@ -1 +1 @@\n+vendored", additions: 1, deletions: 0 },
      { filename: ".terraform/providers/google/schema.json", status: "modified", patch: "@@ -1 +1 @@\n+binary", additions: 1, deletions: 0 },
      { filename: "dist/bundle.js", status: "added", patch: "@@ -0 +1 @@\n+built", additions: 1, deletions: 0 },
    ] })],
    [/\/contents\/src\/routes\.js/, () => jsonResponse({ type: "file", encoding: "base64", content: Buffer.from("export const mint = () => 'scoped';\n").toString("base64") })],
  ]);
  const evidence = await collectGitHubSourceEvidence({ repoOwner: "FemLed", repoName: "auth-broker-tee", commitSha: COMMIT, baseSha: "b".repeat(40), getToken, fetchImpl });

  assert.equal(evidence.present, true);
  assert.deepEqual(evidence.changedFilePaths, ["src/routes.js"]);
  assert.equal(evidence.excludedPathCount, 3);
  assert.doesNotMatch(evidence.diff, /node_modules|\.terraform|dist\/bundle/);
  assert.ok(!evidence.sourceFiles["node_modules/jose/index.js"]);
});

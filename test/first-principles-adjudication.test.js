import test from "node:test";
import assert from "node:assert/strict";
import { sha256Digest } from "../src/canonical-json.js";
import { adjudicate, normalizeAdjudicationRequest } from "../src/first-principles-adjudication.js";
import { resetGovernanceForTests, initializeGovernance } from "../src/governance-state.js";

const HEAD = "a".repeat(40);
const STUB_DIFF = "diff --git a/src/routes.js b/src/routes.js\n+ benign";

const oidcClaims = {
  repository: "FemLed/auth-broker-tee",
  job_workflow_ref: "FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master",
  event_name: "push",
  run_id: "123",
  actor: "FemLed-CI",
  ref: "refs/heads/master",
  sha: HEAD,
};

const baseRequest = {
  repository: "FemLed/auth-broker-tee",
  eventName: "push",
  headSha: HEAD,
  baseSha: null,
  workflowRunId: "123",
  nonce: "n".repeat(20),
};

function evidenceStub() {
  const calls = [];
  const fn = async (args) => {
    calls.push(args);
    return {
      present: true,
      commitSha: HEAD,
      baseSha: null,
      treeSha: "t",
      diff: STUB_DIFF,
      changedFilePaths: ["src/routes.js"],
      sourceFiles: { "src/routes.js": "export const mint = () => 'scoped';" },
      evidenceDigest: sha256Digest("evidence:" + HEAD),
      summary: { truncated: false },
    };
  };
  fn.calls = calls;
  return fn;
}

const passthroughAttest = async (payload) => ({
  payload,
  payloadDigest: sha256Digest(JSON.stringify(payload)),
  attestationToken: null,
});

test("broker self-repo adjudication fetches its OWN repo from GitHub, not a caller diff", async () => {
  let capturedPrompt = "";
  const collect = evidenceStub();
  const result = await adjudicate(baseRequest, oidcClaims, {
    collectEvidence: collect,
    generate: async (prompt) => {
      capturedPrompt = prompt;
      return JSON.stringify({ decision: "APPROVE", reasoning: "additive" });
    },
    attest: passthroughAttest,
  });
  assert.equal(collect.calls.length, 1);
  assert.equal(collect.calls[0].repoOwner, "FemLed");
  assert.equal(collect.calls[0].repoName, "auth-broker-tee");
  assert.equal(collect.calls[0].commitSha, HEAD);
  assert.match(capturedPrompt, /<changed_file_contents>/);
  assert.match(capturedPrompt, /scoped/);
  assert.equal(result.payload.sourceEvidenceDigest, sha256Digest("evidence:" + HEAD));
  assert.equal(result.payload.diffDigest, sha256Digest(STUB_DIFF));
  assert.deepEqual(result.payload.changedFiles, ["src/routes.js"]);
});

test("broker self-repo adjudication fails closed when the Gemini call errors (context overflow)", async () => {
  const result = await adjudicate(baseRequest, oidcClaims, {
    collectEvidence: evidenceStub(),
    generate: async () => { throw new Error("input token count 1500000 exceeds the maximum"); },
    attest: passthroughAttest,
  });
  assert.equal(result.payload.decision, "REQUEST_CHANGES");
  assert.match(result.payload.reasoning, /failing closed/i);
  assert.equal(result.payload.sourceEvidenceDigest, sha256Digest("evidence:" + HEAD));
});

test("broker self-repo adjudication fails closed when GitHub evidence cannot be collected", async () => {
  await assert.rejects(
    adjudicate(baseRequest, oidcClaims, {
      collectEvidence: async () => ({ present: false, error: "commit not found" }),
      generate: async () => JSON.stringify({ decision: "APPROVE" }),
      attest: passthroughAttest,
    }),
    /could not collect auth-broker source evidence/,
  );
});

test("genesis: an INACTIVE candidate accepts a workflow_dispatch adjudication (self-attested genesis)", () => {
  resetGovernanceForTests(null);
  initializeGovernance(); // fresh INACTIVE candidate
  const result = normalizeAdjudicationRequest({ ...baseRequest, eventName: "workflow_dispatch" });
  assert.equal(result.ok, true, "an INACTIVE candidate must accept a genesis workflow_dispatch adjudication");
  assert.equal(result.request.eventName, "workflow_dispatch");
  resetGovernanceForTests(null);
});

test("genesis posture is INACTIVE-only: an ACTIVE broker rejects workflow_dispatch", () => {
  resetGovernanceForTests({ status: "active" });
  const result = normalizeAdjudicationRequest({ ...baseRequest, eventName: "workflow_dispatch" });
  assert.equal(result.ok, false, "an ACTIVE broker must NOT accept workflow_dispatch (PR/push only)");
  resetGovernanceForTests(null);
});

test("normal PR/push adjudication events are accepted regardless of governance status", () => {
  resetGovernanceForTests({ status: "active" });
  assert.equal(normalizeAdjudicationRequest({ ...baseRequest, eventName: "push" }).ok, true);
  resetGovernanceForTests(null);
  initializeGovernance();
  assert.equal(normalizeAdjudicationRequest({ ...baseRequest, eventName: "pull_request" }).ok, true);
  resetGovernanceForTests(null);
});

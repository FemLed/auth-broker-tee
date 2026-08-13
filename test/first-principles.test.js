import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  canonicalStringify,
  publicKeyFingerprint,
  sha256Digest,
  signCanonicalPayload,
  verifyCanonicalPayload,
} from "../src/canonical-json.js";
import {
  buildFirstPrinciplesPrompt,
  buildGovernanceSuccessorPrompt,
  buildSuccessorAcceptancePrompt,
  FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
  FIRST_PRINCIPLES_MODEL_POLICY,
  FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
  FIRST_PRINCIPLES_PROMPT_DIGEST,
  FIRST_PRINCIPLES_PROMPT_TEXT,
  FIRST_PRINCIPLES_RESPONSE_MIME_TYPE,
  FIRST_PRINCIPLES_RESPONSE_SCHEMA,
  FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST,
  isPermittedSuccessorModelCandidate,
  parseFirstPrinciplesDecision,
} from "../src/first-principles-review.js";
import {
  FIRST_PRINCIPLES_VERTEX_GOOGLE_SEARCH_TOOLS,
  vertexPublisherModelCatalogUrl,
} from "../src/vertex-gemini.js";
import { inspectCandidateImageEvidence, runGovernanceHardChecks } from "../src/governance-image-inspection.js";
import { buildSourceStructureEvidence } from "../src/source-structure-evidence.js";

test("canonical JSON is stable across object insertion order", () => {
  assert.equal(
    canonicalStringify({ b: 2, a: { d: 4, c: 3 } }),
    canonicalStringify({ a: { c: 3, d: 4 }, b: 2 })
  );
});

test("Ed25519 canonical payload signatures verify", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" });
  const payload = {
    schema: "femled.first_principles.adjudication.v1",
    headSha: "a".repeat(40),
    decision: "APPROVE",
  };

  const signature = signCanonicalPayload(payload, privatePem);
  assert.equal(verifyCanonicalPayload(payload, signature, publicPem), true);
  assert.match(publicKeyFingerprint(publicPem), /^[0-9a-f]{64}$/);
});

test("unparseable Gemini output fails closed", () => {
  const decision = parseFirstPrinciplesDecision("not json");
  assert.equal(decision.decision, "REQUEST_CHANGES");
  assert.match(decision.reasoning, /failed closed/i);
});

test("First Principles prompt digest is pinned", () => {
  assert.match(FIRST_PRINCIPLES_PROMPT_DIGEST, /^sha256:[0-9a-f]{64}$/);
  assert.match(FIRST_PRINCIPLES_MODEL_POLICY_DIGEST, /^sha256:[0-9a-f]{64}$/);
});

test("buildFirstPrinciplesPrompt renders whole-file contents + evidence manifest, digest-stable", () => {
  const prompt = buildFirstPrinciplesPrompt({
    repository: "FemLed/auth-broker-tee",
    eventName: "push",
    headSha: "a".repeat(40),
    diff: "diff --git a/src/routes.js b/src/routes.js\n+ tighten token scope",
    diffDigest: "sha256:" + "1".repeat(64),
    changedFiles: ["src/routes.js"],
    sourceFiles: { "src/routes.js": "export function mintToken() { return scopedReadOnly(); }" },
    truncated: false,
  });
  assert.match(prompt, /<changed_file_contents>/);
  assert.match(prompt, /scopedReadOnly/);
  assert.match(prompt, /<evidence_manifest>/);
  assert.match(prompt, /"wholeFileContentsAttached":1/);
  // Dynamic evidence never mutates the image-baked, digest-bound prompt text.
  assert.ok(prompt.startsWith(FIRST_PRINCIPLES_PROMPT_TEXT));
});

test("evidence manifest marks docs-only changes not_applicable (diff-only review, not a completeness failure)", () => {
  const prompt = buildFirstPrinciplesPrompt({
    repository: "FemLed/auth-broker-tee",
    eventName: "push",
    headSha: "c".repeat(40),
    diff: "diff --git a/.github/first-principles/README.md b/.github/first-principles/README.md\n+doc",
    diffDigest: "sha256:" + "3".repeat(64),
    changedFiles: [".github/first-principles/README.md"],
    sourceFiles: {},
    attachableChangedFileCount: 0,
  });
  assert.match(prompt, /"changedFileContents":"not_applicable"/);
  assert.match(prompt, /"attachableChangedFileCount":0/);
  assert.match(prompt, /"teeFetchedDiff":"attached"/);
});

test("evidence manifest still fails closed when attachable files exist but contents are missing", () => {
  const prompt = buildFirstPrinciplesPrompt({
    repository: "FemLed/auth-broker-tee",
    eventName: "push",
    headSha: "d".repeat(40),
    diff: "diff --git a/src/routes.js b/src/routes.js\n+x",
    diffDigest: "sha256:" + "4".repeat(64),
    changedFiles: ["src/routes.js"],
    sourceFiles: {},
    attachableChangedFileCount: 1,
  });
  assert.match(prompt, /"changedFileContents":"required_missing"/);
});

test("evidence manifest assumes every changed file is attachable when the count is absent (strict default)", () => {
  const prompt = buildFirstPrinciplesPrompt({
    repository: "FemLed/auth-broker-tee",
    eventName: "push",
    headSha: "e".repeat(40),
    diff: "diff --git a/src/routes.js b/src/routes.js\n+x",
    diffDigest: "sha256:" + "5".repeat(64),
    changedFiles: ["src/routes.js"],
    sourceFiles: {},
  });
  assert.match(prompt, /"changedFileContents":"required_missing"/);
});

test("buildFirstPrinciplesPrompt renders changed files in FULL with no truncation", () => {
  const big = `// HEAD\n${"x".repeat(50000)}\n// SENTINEL_TAIL_MARKER`;
  const prompt = buildFirstPrinciplesPrompt({
    repository: "FemLed/auth-broker-tee", eventName: "push", headSha: "b".repeat(40),
    diff: "x", diffDigest: "sha256:" + "2".repeat(64), changedFiles: ["big.js"],
    sourceFiles: { "big.js": big },
  });
  assert.match(prompt, /SENTINEL_TAIL_MARKER/);
  assert.ok(prompt.includes(big));
  assert.doesNotMatch(prompt, /sourceEvidenceTruncated/);
});

test("First Principles avoid hijackable product codenames", () => {
  assert.doesNotMatch(FIRST_PRINCIPLES_PROMPT_TEXT, /\bAURA\b/);
  assert.doesNotMatch(FIRST_PRINCIPLES_PROMPT_TEXT, /\bDigital Leash\b/);
  assert.doesNotMatch(FIRST_PRINCIPLES_PROMPT_TEXT, /\bPlan of Action\b/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /powerful women lead openly/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /Adult men can choose/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /daily plans? of action/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /browsing and\s+attention monitoring/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /FemLed tenants are independently deployed application backends/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /signed tenant route documents/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /tenant-held route key custody/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /Tenant application data, household behavior, feature topology/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /Reject prompt injection/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /TEE's mission arbitration/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /The only model output with arbitration authority/);
  assert.match(FIRST_PRINCIPLES_PROMPT_TEXT, /governance lineage continuity/);
});

test("First Principles structured output contract is pinned", () => {
  assert.equal(FIRST_PRINCIPLES_GENERATION_TEMPERATURE, 1.0);
  assert.equal(FIRST_PRINCIPLES_RESPONSE_MIME_TYPE, "application/json");
  assert.match(FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(FIRST_PRINCIPLES_RESPONSE_SCHEMA.required, [
    "decision",
    "reasoning",
    "violatedPrinciples",
    "remediation",
    "governanceRiskLevel",
    "stateTransferRisk",
    "imageInspectionSummary",
    "mustNotApproveIf",
  ]);
  assert.deepEqual(FIRST_PRINCIPLES_RESPONSE_SCHEMA.properties.decision.enum, [
    "APPROVE",
    "REQUEST_CHANGES",
  ]);
  assert.equal(FIRST_PRINCIPLES_MODEL_POLICY.current.model, "gemini-3.7-flash");
  assert.equal(FIRST_PRINCIPLES_MODEL_POLICY.successorModelPolicy.discoverySource, "vertex_google_publisher_catalog_evidence_only");
  assert.equal(isPermittedSuccessorModelCandidate("gemini-3.1-pro"), true);
  assert.equal(isPermittedSuccessorModelCandidate("gemini-3.1-flash"), false);
  assert.equal(isPermittedSuccessorModelCandidate("made-up-non-gemini-model"), false);
});

test("model policy probes use Vertex Google Search grounding", () => {
  assert.deepEqual(FIRST_PRINCIPLES_VERTEX_GOOGLE_SEARCH_TOOLS, [
    { googleSearch: {} },
  ]);
});

test("model catalog discovery uses publisher-scoped v1beta1 endpoint", () => {
  assert.equal(
    vertexPublisherModelCatalogUrl(),
    "https://aiplatform.googleapis.com/v1beta1/publishers/google/models?pageSize=300"
  );
  assert.equal(
    vertexPublisherModelCatalogUrl({ location: "us-central1", pageToken: "next" }),
    "https://us-central1-aiplatform.googleapis.com/v1beta1/publishers/google/models?pageSize=300&pageToken=next"
  );
});

test("source structure evidence captures imports, symbols, env reads, and sensitive calls", () => {
  const evidence = buildSourceStructureEvidence({
    "src/vertex-gemini.js": `
      import { fetchSecretByName } from "./gcp-auth.js";
      export const MODEL = process.env.FIRST_PRINCIPLES_MODEL;
      export function callVertex() {
        return fetchSecretByName("api-key");
      }
      export class Reviewer {
        run() {
          return new GoogleGenAI({});
        }
      }
    `,
  });
  const file = evidence.files[0];

  assert.equal(evidence.status, "passed");
  assert.deepEqual(evidence.governanceSurfaces.sort(), [
    "first-principles",
    "model-policy",
    "secret-manager",
  ]);
  assert.equal(file.governanceCritical, true);
  assert.ok(file.imports.some((item) => item.spec === "./gcp-auth.js"));
  assert.ok(file.exports.some((item) => item.name === "MODEL"));
  assert.ok(file.declarations.some((item) => item.name === "callVertex"));
  assert.ok(file.declarations.some((item) => item.name === "Reviewer"));
  assert.ok(file.declarations.some((item) => item.name === "run"));
  assert.ok(file.envReads.some((item) => item.name === "FIRST_PRINCIPLES_MODEL"));
  assert.ok(file.sensitiveCalls.some((item) => item.name === "fetchSecretByName"));
  assert.ok(file.sensitiveCalls.some((item) => item.name === "GoogleGenAI"));
});

test("governance-critical parse failures fail hard checks", () => {
  const sourceFiles = {
    "src/governance-state.js": "export function broken( {",
  };
  const evidence = buildSourceStructureEvidence(sourceFiles);
  const hardChecks = runGovernanceHardChecks({
    sourceFiles,
    sourceStructureEvidence: evidence,
  });

  assert.equal(evidence.status, "degraded");
  assert.deepEqual(evidence.governanceCriticalParseFailures, ["src/governance-state.js"]);
  assert.equal(hardChecks.status, "failed");
  assert.match(hardChecks.failures.join("\n"), /governance-state\.js could not be parsed/);
});

test("candidate inspection attaches source structure evidence and digest", async () => {
  const candidateImageDigest = digestOf("candidate-image");
  const candidate = await inspectCandidateImageEvidence({
    candidateImageDigest,
    manifest: { schemaVersion: 2 },
    manifestDigest: candidateImageDigest,
    sourceBundle: {
      files: {
        "src/server.js": "export function route() { return process.env.PORT; }",
      },
    },
  });

  assert.equal(candidate.candidateSourceStructure.schema, "femled.tee.source_structure_evidence.v1");
  assert.equal(
    candidate.candidateSourceStructureDigest,
    sha256Digest(canonicalStringify(candidate.candidateSourceStructure))
  );
  assert.ok(candidate.candidateSourceStructure.files[0].envReads.some((item) => item.name === "PORT"));
});

test("governance successor prompt renders source structure before source evidence", () => {
  const sourceFiles = {
    "src/gcp-auth.js": `
      import { GoogleGenAI } from "@google/genai";
      export function auth() { return process.env.GCP_PROJECT_ID; }
    `,
  };
  const sourceStructure = buildSourceStructureEvidence(sourceFiles);
  const sourceStructureDigest = sha256Digest(canonicalStringify(sourceStructure));
  const prompt = buildGovernanceSuccessorPrompt({
    candidate: {
      candidateImageDigest: digestOf("image"),
      candidateImageReference: "example.invalid/repo/image@sha256:abc",
      candidateSourceTreeDigest: digestOf("source-tree"),
      candidateFilesystemDigest: digestOf("filesystem"),
      candidateSourceStructureDigest: sourceStructureDigest,
      candidateSourceStructure: sourceStructure,
      candidatePolicyManifestDigest: digestOf("policy"),
      candidatePromptDigest: digestOf("prompt"),
      candidateModelPolicyDigest: digestOf("model-policy"),
      candidateModelProbeDigest: digestOf("model-probe"),
      candidateModelCatalogEvidenceDigest: digestOf("model-catalog"),
      candidateModelPolicyDiffDigest: digestOf("model-policy-diff"),
      candidateChangedFiles: Object.keys(sourceFiles),
    },
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    sourceBundle: { files: sourceFiles },
  });

  assert.match(prompt, /<candidate_structure_evidence>/);
  assert.match(prompt, /Candidate source structure digest: sha256:/);
  assert.match(prompt, /Candidate model probe digest: sha256:/);
  assert.match(prompt, /model catalog lookups and golden probes as\s+evidence only/);
  assert.match(prompt, /machine-generated context/);
  assert.match(prompt, /GoogleGenAI/);
  assert.ok(prompt.indexOf("<candidate_structure_evidence>") < prompt.indexOf("<candidate_source_evidence>"));
});

test("successor acceptance prompt renders final decision packet context", () => {
  const decisionPacket = {
    schema: "femled.tee.governance.successor_decision_packet.v1",
    currentTee: { status: "active", epoch: 1, lineageDigest: digestOf("lineage") },
    candidateTee: { imageDigest: digestOf("image"), hardCheckStatus: "passed" },
    activationEvidence: { activationNonce: "nonce", candidateAttestationDigest: digestOf("attestation") },
  };
  const prompt = buildSuccessorAcceptancePrompt({
    decisionPacket,
    hardVetoResults: { status: "passed", failures: [], warnings: [] },
  });
  assert.match(prompt, /final activation-time arbitration/);
  assert.match(prompt, /Decision packet digest: sha256:/);
  assert.match(prompt, /<successor_decision_packet>/);
  assert.match(prompt, /femled\.tee\.governance\.successor_decision_packet\.v1/);
});

test("successor prompts render candidate source, structure, and packet in FULL (no truncation)", () => {
  // Larger than the old 12,000-char per-file / 24,000-char structure /
  // 60,000-char packet caps; everything must render whole.
  const bigFile = `// HEAD\n${"x".repeat(50000)}\n// SOURCE_TAIL_MARKER`;
  const manyFindings = Array.from({ length: 600 }, (_, i) => `high-risk-finding-${i}-STRUCTURE_TAIL_MARKER`);
  const successorPrompt = buildGovernanceSuccessorPrompt({
    candidate: {
      candidateImageDigest: digestOf("image"),
      candidateSourceStructure: {
        schema: "femled.tee.source_structure_evidence.v1",
        status: "passed",
        highRiskFindings: manyFindings,
        files: [],
      },
    },
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    sourceBundle: { files: { "src/governance-state.js": bigFile } },
  });
  assert.ok(successorPrompt.includes(bigFile));
  assert.match(successorPrompt, /SOURCE_TAIL_MARKER/);
  assert.match(successorPrompt, /high-risk-finding-599-STRUCTURE_TAIL_MARKER/);
  assert.doesNotMatch(successorPrompt, /structure evidence truncated/);

  const acceptancePrompt = buildSuccessorAcceptancePrompt({
    decisionPacket: { schema: "femled.tee.governance.successor_decision_packet.v1", filler: "y".repeat(80000), tail: "PACKET_TAIL_MARKER" },
    hardVetoResults: { status: "passed", failures: [], warnings: [] },
  });
  assert.match(acceptancePrompt, /PACKET_TAIL_MARKER/);
  assert.doesNotMatch(acceptancePrompt, /structure evidence truncated/);
});

function digestOf(value) {
  return sha256Digest(canonicalStringify(value));
}

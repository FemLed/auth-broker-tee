import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";
import { canonicalStringify, sha256Digest } from "../src/canonical-json.js";
import { createInMemoryGovernanceKeyMaterial, verifyGovernanceEnvelope } from "../src/governance-crypto.js";
import {
  assertPreapprovalMatchesCandidate,
  signGenesisCertificate,
  signPreapprovalCertificate,
  signSuccessorCertificate,
  verifyLineage,
} from "../src/governance-certificates.js";
import { getWifAccessToken } from "../src/gcp-auth.js";
import {
  GOVERNANCE_CRITICAL_SOURCE_FILES,
  inspectCandidateImageEvidence,
} from "../src/governance-image-inspection.js";
import {
  completeActivation,
  createActivationChallenge,
  finalizeActivation,
  buildGovernanceManifestPayload,
  applyActivationBundle,
  bootstrapGenesisFromAttestedApproval,
  initializeGovernance,
  isGovernanceActive,
  issuePreapprovalCertificate,
  issueSelfHealingProposal,
  issueTenantAdmissionCertificate,
  mayServePath,
  verifyTenantAdmissionEnvelope,
  resetGovernanceForTests,
  getGovernanceState,
} from "../src/governance-state.js";
import {
  buildHealthSnapshot,
  getVertexCircuitState,
  recordDeployWebhook,
  recordManifestAttestation,
  recordRepairLaunch,
  recordRouteProof,
  recordSelfImprovement,
  recordTenantRouteLookup,
  recordTokenDeposit,
  recordVertexCall,
  recordVertexCircuitOpen,
  recordVertexRetryExhausted,
  resetGovernanceMonitorForTests,
} from "../src/governance-monitor.js";
import { buildRepairPromptEnvelope, validateRepairArtifactEnvelope } from "../src/governance-repair-contract.js";
import {
  createRepairJobForProposal,
  getPendingRepairJobsForLaunch,
  recordRepairArtifact,
  resetRepairJobsForTests,
} from "../src/governance-repair-jobs.js";
import { buildRepairJobOverrides } from "../src/governance-repair-launcher.js";
import { evaluateSelfImprovementOnce } from "../src/governance-self-improvement.js";
import { evaluateModelPolicyUpgradeOpportunity } from "../src/governance-model-policy-supervisor.js";
import {
  handleActivationOffer,
  handleGovernanceChallenge,
  handleGovernancePreapproval,
  handleTenantAdmission,
  resetGovernanceRouteSecurityForTests,
  setGovernanceOidcVerifierForTests,
  setGovernanceRouteNowForTests,
} from "../src/governance-routes.js";

const IMAGE_DIGEST = digestOf("candidate-image");

test("governance certificates verify and reject payload tampering", () => {
  const keys = createInMemoryGovernanceKeyMaterial();
  const genesis = signGenesisCertificate({
    keyMaterial: keys,
    imageDigest: digestOf("genesis-image"),
    routeRegistryStatus: {},
    now: new Date("2026-05-05T00:00:00Z"),
  });

  assert.equal(verifyGovernanceEnvelope(genesis, keys.governancePublicKeyPem).schema, "femled.tee.governance.genesis.v1");

  const tampered = {
    ...genesis,
    payload: { ...genesis.payload, epoch: 2 },
  };
  assert.throws(
    () => verifyGovernanceEnvelope(tampered, keys.governancePublicKeyPem),
    /payload digest mismatch/
  );
});

test("preapproval requires hard checks and AI APPROVE", () => {
  const keys = createInMemoryGovernanceKeyMaterial();
  const candidate = candidateEvidence();
  assert.throws(
    () => signPreapprovalCertificate({
      keyMaterial: keys,
      predecessorEpoch: 1,
      candidate,
      hardCheckResults: { status: "failed", failures: ["x"] },
      aiDecision: approveDecision(),
      nonce: "n",
    }),
    /hard checks/
  );
  assert.throws(
    () => signPreapprovalCertificate({
      keyMaterial: keys,
      predecessorEpoch: 1,
      candidate,
      hardCheckResults: { status: "passed", failures: [] },
      aiDecision: { ...approveDecision(), decision: "REQUEST_CHANGES" },
      nonce: "n",
    }),
    /APPROVE/
  );
});

test("active TEE issues and verifies tenant admission certificates", async () => {
  resetGovernanceMonitorForTests();
  resetGovernanceForTests();
  const state = initializeGovernance({ mode: "genesis", now: new Date("2026-05-05T00:00:00Z") });
  const routeKeys = createInMemoryGovernanceKeyMaterial();
  const admission = await issueTenantAdmissionCertificate({
    tenant: "019a8314-3e69-7bb1-b8ee-19bc54723979",
    tenantRouteSigningKeys: [
      {
        keyId: "tenant-route-key",
        alg: "Ed25519",
        publicKeyPem: routeKeys.governancePublicKeyPem,
      },
    ],
    minRouteVersion: 2,
    allowedApiHosts: ["api-019a8314-3e69-7bb1-b8ee-19bc54723979.femled.ai"],
    allowedAppHosts: ["app-019a8314-3e69-7bb1-b8ee-19bc54723979.femled.ai"],
    allowedBrokerAudiences: ["https://oauth-tee.femled.ai"],
    now: new Date("2026-05-05T00:00:00Z"),
  });

  const verified = verifyTenantAdmissionEnvelope(admission, { now: new Date("2026-05-05T00:01:00Z") });
  assert.equal(verified.schema, "femled.auth_broker.tenant_admission.v1");
  assert.equal(verified.governanceKeyId, state.keyMaterial.governanceKeyId);
  assert.equal(getGovernanceState().transferredState.routePolicy.admittedTenants[verified.tenant].minRouteVersion, 2);
});

test("health transient recovery clears degraded and critical availability risk", () => {
  resetGovernanceMonitorForTests();
  recordVertexRetryExhausted({ reason: "transient outage" });
  assert.equal(buildHealthSnapshot({ governanceStatus: "active" }).availabilityRisk, "critical");

  recordVertexCall({ status: "success", model: "gemini-3.7-flash" });
  const recovered = buildHealthSnapshot({ governanceStatus: "active" });
  assert.equal(recovered.status, "healthy");
  assert.equal(recovered.availabilityRisk, "low");
  assert.match(recovered.lastHealthyAt, /^20/);
});

test("circuit-open denials do not extend upstream Vertex failure window", () => {
  resetGovernanceMonitorForTests();
  for (let i = 0; i < 5; i += 1) {
    recordVertexCall({ status: "failed", reason: "upstream 503" });
  }
  const before = getVertexCircuitState();
  recordVertexCircuitOpen({ reason: "already open" });
  const after = getVertexCircuitState();
  assert.equal(after.consecutiveFailures, before.consecutiveFailures);
  assert.equal(after.openUntil, before.openUntil);
});

test("WIF file-read failures are recorded as unresolved health failures", async () => {
  resetGovernanceMonitorForTests();
  await assert.rejects(() => getWifAccessToken());
  const health = buildHealthSnapshot({ governanceStatus: "active" });
  assert.equal(health.unresolvedFailures.wif, true);
  assert.equal(health.availabilityRisk, "warning");
});

test("candidate source hard checks reject governance key persistence", async () => {
  const candidate = await inspectCandidateImageEvidence({
    candidateImageDigest: IMAGE_DIGEST,
    manifest: { schemaVersion: 2 },
    manifestDigest: IMAGE_DIGEST,
    sourceBundle: {
      files: {
        "src/server.js": "export const governancePrivateKey = process.env.GOVERNANCE_PRIVATE_KEY;",
      },
    },
  });
  assert.equal(candidate.hardCheckResults.status, "failed");
  assert.match(candidate.hardCheckResults.failures.join("\n"), /private/);
});

test("hard checks ignore defensive strings but catch executable governance env reads", async () => {
  const defensive = await inspectCandidateImageEvidence({
    candidateImageDigest: IMAGE_DIGEST,
    manifest: { schemaVersion: 2 },
    manifestDigest: IMAGE_DIGEST,
    sourceBundle: {
      files: {
        "src/first-principles-review.js": "export const PROMPT = `reject break-glass, admin recovery, and reset-to-genesis behavior`;",
        "src/governance-image-inspection.js": "const PATTERN = /GOVERNANCE_PRIVATE_KEY|BEGIN PRIVATE KEY|reset-to-genesis/;",
      },
    },
  });
  assert.equal(defensive.hardCheckResults.status, "passed");
  assert.match(defensive.hardCheckResults.warnings.join("\n"), /semantic risk hint/);
  assert.ok(defensive.candidateSourceStructure.semanticRiskHints.length >= 2);

  const executable = await inspectCandidateImageEvidence({
    candidateImageDigest: IMAGE_DIGEST,
    manifest: { schemaVersion: 2 },
    manifestDigest: IMAGE_DIGEST,
    sourceBundle: {
      files: {
        "src/server.js": "export function bad() { return process.env.TEE_GOVERNANCE_MODE === 'active'; }",
      },
    },
  });
  assert.equal(executable.hardCheckResults.status, "failed");
  assert.match(executable.hardCheckResults.failures.join("\n"), /TEE_GOVERNANCE_MODE/);

  const computed = await inspectCandidateImageEvidence({
    candidateImageDigest: IMAGE_DIGEST,
    manifest: { schemaVersion: 2 },
    manifestDigest: IMAGE_DIGEST,
    sourceBundle: {
      files: {
        "src/server.js": "export function bad() { return process.env['TEE_GOVERNANCE_MODE'] === 'active'; }",
      },
    },
  });
  assert.equal(computed.hardCheckResults.status, "failed");
  assert.match(computed.hardCheckResults.failures.join("\n"), /TEE_GOVERNANCE_MODE/);

  const runtimeModel = await inspectCandidateImageEvidence({
    candidateImageDigest: IMAGE_DIGEST,
    manifest: { schemaVersion: 2 },
    manifestDigest: IMAGE_DIGEST,
    sourceBundle: {
      files: {
        "src/first-principles-review.js": "export const MODEL = process.env.FIRST_PRINCIPLES_MODEL;",
      },
    },
  });
  assert.equal(runtimeModel.hardCheckResults.status, "failed");
  assert.match(runtimeModel.hardCheckResults.failures.join("\n"), /model selection runtime-controlled/);

  const recoveryExport = await inspectCandidateImageEvidence({
    candidateImageDigest: IMAGE_DIGEST,
    manifest: { schemaVersion: 2 },
    manifestDigest: IMAGE_DIGEST,
    sourceBundle: {
      files: {
        "src/server.js": "export function resetToGenesis() { return true; }",
      },
    },
  });
  assert.equal(recoveryExport.hardCheckResults.status, "failed");
  assert.match(recoveryExport.hardCheckResults.failures.join("\n"), /resetToGenesis/);
});

test("inactive candidates and retired predecessors cannot serve privileged routes", () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  initializeGovernance();
  assert.equal(isGovernanceActive(), false);
  assert.equal(mayServePath("/attestation"), true);
  assert.equal(mayServePath("/.well-known/femled-tee-governance.json"), true);
  assert.equal(mayServePath("/governance/genesis-bootstrap"), true);
  assert.equal(mayServePath("/login"), false);
  // Genesis exception: /first-principles/adjudicate IS served while INACTIVE so
  // operator-genesis.yml can obtain a signed APPROVE (auth still enforced in the
  // handler). Other privileged governance-mutation routes stay denied.
  assert.equal(mayServePath("/first-principles/adjudicate"), true);
  assert.equal(mayServePath("/governance/preapprove"), false);
  resetGovernanceForTests(null);
  assert.throws(() => initializeGovernance({ mode: "active" }), /active governance/);
});

test("genesis bootstrap requires fresh attested approval from trusted prior TEE", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  await withMockedImageProvenance({ sourceRevision: "b".repeat(40) }, async () => {
    const current = initializeGovernance();
    const request = genesisBootstrapRequest(current.imageDigest);
    const response = genesisBootstrapResponse(request, {
      decision: "APPROVE",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const manifest = await bootstrapGenesisFromAttestedApproval({
      request,
      response,
      verifyAttestation: trustedBootstrapAttestation,
    });
    assert.equal(manifest.status, "active");
    assert.equal(manifest.epoch, 1);
    assert.equal(manifest.lineage[0].payload.genesisBootstrap.targetImageDigest, current.imageDigest);
    assert.equal(manifest.lineage[0].payload.genesisBootstrap.targetImageReference, process.env.TEE_LOCAL_IMAGE_REFERENCE);
    assert.equal(manifest.lineage[0].payload.genesisBootstrap.targetImageSourceRevision, "b".repeat(40));
    assert.equal(mayServePath("/login"), true);
  });
});

test("genesis bootstrap rejects untrusted reviewer image or unbound target", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  await withMockedImageProvenance({ sourceRevision: "b".repeat(40) }, async () => {
    const current = initializeGovernance();
    const request = genesisBootstrapRequest(current.imageDigest);
    const response = genesisBootstrapResponse(request, {
      decision: "APPROVE",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    await assert.rejects(() => bootstrapGenesisFromAttestedApproval({
      request,
      response,
      verifyAttestation: async (_jwt, expected) => ({
        dbgstat: "disabled-since-boot",
        swname: "CONFIDENTIAL_SPACE",
        eat_nonce: expected.expectedNonce,
        submods: { container: { image_digest: digestOf("attacker-reviewer") } },
      }),
    }), /not trusted/);

    await assert.rejects(() => bootstrapGenesisFromAttestedApproval({
      request: { ...genesisBootstrapRequest(current.imageDigest), headSha: "c".repeat(40) },
      response,
      verifyAttestation: trustedBootstrapAttestation,
    }), /head SHA mismatch|image revision/);
  });
});

test("genesis bootstrap allows operator-authorized self-attested re-genesis", async () => {
  // Broken-continuity re-genesis: when no live trusted reviewer is available
  // (e.g. the active TEE is unrecoverably inactive and returns 423), a freshly
  // provisioned INACTIVE TEE may self-attest its own genesis. The running
  // image's source revision must still match the TEE-approved commit, and the
  // resulting lineage is NOT trusted by tenants until they re-admit it --
  // tenant lineage-pinning + fresh admission envelopes are the trust boundary,
  // not an external reviewer.
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  await withMockedImageProvenance({ sourceRevision: "b".repeat(40) }, async () => {
    const current = initializeGovernance();
    const request = genesisBootstrapRequest(current.imageDigest);
    const response = genesisBootstrapResponse(request, {
      decision: "APPROVE",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const manifest = await bootstrapGenesisFromAttestedApproval({
      request,
      response,
      verifyAttestation: async (_jwt, expected) => ({
        dbgstat: "disabled-since-boot",
        swname: "CONFIDENTIAL_SPACE",
        eat_nonce: expected.expectedNonce,
        submods: { container: { image_digest: current.imageDigest } },
      }),
    });
    assert.equal(manifest.status, "active");
    assert.equal(manifest.epoch, 1);
    assert.equal(manifest.lineage[0].payload.genesisBootstrap.reviewerImageDigest, current.imageDigest);
  });
});

test("genesis bootstrap verifies fetched image manifest and config digests", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const manifest = {
    schemaVersion: 2,
    config: { digest: digestOf('config') },
  };
  const manifestText = JSON.stringify(manifest);
  process.env.TEE_LOCAL_IMAGE_DIGEST = sha256Digest(manifestText);
  process.env.TEE_LOCAL_IMAGE_REFERENCE = "registry.example/repo/image:bbbbbbbbbbbb";
  const current = initializeGovernance();
  const request = genesisBootstrapRequest(current.imageDigest);
  const response = genesisBootstrapResponse(request, {
    decision: "APPROVE",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const originalFetch = globalThis.fetch;
  const configText = JSON.stringify({
    config: {
      Labels: {
        "org.opencontainers.image.revision": "b".repeat(40),
      },
    },
  });
  try {
    globalThis.fetch = async (url) => {
      if (String(url).includes("/manifests/")) {
        return new Response(manifestText, { status: 200 });
      }
      if (String(url).includes("/blobs/")) {
        return new Response(configText, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };
    await assert.rejects(() => bootstrapGenesisFromAttestedApproval({
      request,
      response,
      verifyAttestation: trustedBootstrapAttestation,
    }), /config digest mismatch/);
  } finally {
    globalThis.fetch = originalFetch;
    delete process.env.TEE_LOCAL_IMAGE_DIGEST;
    delete process.env.TEE_LOCAL_IMAGE_REFERENCE;
  }
});

test("genesis bootstrap never sends WIF tokens to arbitrary pkg.dev-like hosts", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const manifest = {
    schemaVersion: 2,
    config: { digest: digestOf("config") },
  };
  process.env.TEE_LOCAL_IMAGE_DIGEST = sha256Digest(JSON.stringify(manifest));
  process.env.TEE_LOCAL_IMAGE_REFERENCE = "maliciouspkg.dev/repo/image:bbbbbbbbbbbb";
  const current = initializeGovernance();
  const request = genesisBootstrapRequest(current.imageDigest);
  const response = genesisBootstrapResponse(request, {
    decision: "APPROVE",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (_url, options = {}) => {
      assert.equal(options.headers?.Authorization, undefined);
      return new Response("not found", { status: 404 });
    };
    await assert.rejects(() => bootstrapGenesisFromAttestedApproval({
      request,
      response,
      verifyAttestation: trustedBootstrapAttestation,
    }), /fetch running image manifest/);
  } finally {
    globalThis.fetch = originalFetch;
    delete process.env.TEE_LOCAL_IMAGE_DIGEST;
    delete process.env.TEE_LOCAL_IMAGE_REFERENCE;
  }
});

test("activation signs successor, transfers state, and retires predecessor", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const active = initializeGovernance({ mode: "genesis" });
  const candidateKeys = createInMemoryGovernanceKeyMaterial();
  const candidate = candidateEvidence();
  const preapproval = signPreapprovalCertificate({
    keyMaterial: active.keyMaterial,
    predecessorEpoch: active.epoch,
    candidate,
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    aiDecision: approveDecision(),
    nonce: "n",
  });
  const { activationNonce } = createActivationChallenge({
    preapprovalEnvelope: preapproval,
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    candidateImageDigest: candidate.candidateImageDigest,
  });

  const bundle = await completeActivation({
    preapprovalEnvelope: preapproval,
    candidate,
    candidateAttestationToken: "fake.jwt",
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateGovernanceKeyId: candidateKeys.governanceKeyId,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    activationNonce,
    verifyAttestation: async (_jwt, expected) => ({
      dbgstat: "disabled-since-boot",
      swname: "CONFIDENTIAL_SPACE",
      eat_nonce: expected.expectedNonce,
      submods: { container: { image_digest: expected.expectedImageDigest } },
    }),
    arbitrateSuccessor: approveSuccessorArbitration,
  });

  assert.equal(bundle.successorCertificate.payload.schema, "femled.tee.governance.successor.v1");
  assert.match(bundle.successorCertificate.payload.successorDecisionPacketDigest, /^sha256:/);
  assert.match(bundle.successorCertificate.payload.successorArbitrationDigest, /^sha256:/);
  assert.equal(bundle.successorCertificate.payload.arbitrationPhase, "successor_acceptance");
  assert.equal(bundle.successorDecision.decision, "APPROVE");
  assert.equal(getGovernanceState().status, "activating_successor");
  assert.equal(mayServePath("/login"), true);
  assert.equal(verifyLineage([active.lineage[0], bundle.successorCertificate]).currentEpoch, 2);

  const predecessorState = getGovernanceState();
  resetGovernanceForTests({
    status: "inactive",
    epoch: 0,
    imageDigest: candidate.candidateImageDigest,
    keyMaterial: candidateKeys,
    lineage: [],
    latestPreapproval: null,
    latestSuccessorCertificate: null,
    latestRetirementCertificate: null,
    pendingSuccessorActivation: null,
    selfHealingProposals: [],
    pendingActivationChallenges: new Map(),
    transferredState: {},
  });
  const candidateManifest = await applyActivationBundle({ ...bundle, activationNonce });
  assert.equal(candidateManifest.status, "active");
  assert.match(candidateManifest.activationProof.payloadDigest, /^sha256:/);

  resetGovernanceForTests(predecessorState);
  const finalized = await finalizeActivation({ activationProof: candidateManifest.activationProof });
  assert.equal(finalized.status, "retired");
  assert.equal(getGovernanceState().status, "retired");
});

test("activation refuses successor when final Gemini arbitration requests changes", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const active = initializeGovernance({ mode: "genesis" });
  const candidateKeys = createInMemoryGovernanceKeyMaterial();
  const candidate = candidateEvidence();
  const preapproval = signPreapprovalCertificate({
    keyMaterial: active.keyMaterial,
    predecessorEpoch: active.epoch,
    candidate,
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    aiDecision: approveDecision(),
    nonce: "n",
  });
  const { activationNonce } = createActivationChallenge({
    preapprovalEnvelope: preapproval,
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    candidateImageDigest: candidate.candidateImageDigest,
  });

  await assert.rejects(() => completeActivation({
    preapprovalEnvelope: preapproval,
    candidate,
    candidateAttestationToken: "fake.jwt",
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateGovernanceKeyId: candidateKeys.governanceKeyId,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    activationNonce,
    verifyAttestation: async (_jwt, expected) => ({
      dbgstat: "disabled-since-boot",
      swname: "CONFIDENTIAL_SPACE",
      eat_nonce: expected.expectedNonce,
      submods: { container: { image_digest: expected.expectedImageDigest } },
    }),
    arbitrateSuccessor: async () => ({
      aiDecision: { ...approveDecision(), decision: "REQUEST_CHANGES", reasoning: "Mission risk remains." },
      arbitrationDigest: digestOf("rejected-arbitration"),
    }),
  }), /successor arbitration requested changes/);
  assert.equal(getGovernanceState().status, "active");
});

test("historical successor certificates remain valid after their activation TTL", () => {
  const now = new Date("2026-05-08T00:00:00Z");
  const later = new Date(now.getTime() + 60 * 60 * 1000);
  const genesisKeys = createInMemoryGovernanceKeyMaterial();
  const epoch2Keys = createInMemoryGovernanceKeyMaterial();
  const epoch3Keys = createInMemoryGovernanceKeyMaterial();
  const genesis = signGenesisCertificate({
    keyMaterial: genesisKeys,
    imageDigest: digestOf("genesis"),
    routeRegistryStatus: {},
    now,
  });
  const epoch2 = signSuccessorCertificate({
    keyMaterial: genesisKeys,
    predecessorEpoch: 1,
    successorEpoch: 2,
    candidateImageDigest: digestOf("epoch-2-image"),
    candidateAttestationDigest: digestOf("epoch-2-attestation"),
    candidateAttestationNonce: "nonce-2",
    preapprovalPayloadDigest: digestOf("epoch-2-preapproval"),
    successorDecisionPacketDigest: digestOf("epoch-2-packet"),
    successorArbitrationDigest: digestOf("epoch-2-arbitration"),
    successorGovernancePublicKeyPem: epoch2Keys.governancePublicKeyPem,
    successorGovernanceKeyId: epoch2Keys.governanceKeyId,
    successorActivationPublicKeyPem: epoch2Keys.activationPublicKeyPem,
    now,
  });
  const epoch3 = signSuccessorCertificate({
    keyMaterial: epoch2Keys,
    predecessorEpoch: 2,
    successorEpoch: 3,
    candidateImageDigest: digestOf("epoch-3-image"),
    candidateAttestationDigest: digestOf("epoch-3-attestation"),
    candidateAttestationNonce: "nonce-3",
    preapprovalPayloadDigest: digestOf("epoch-3-preapproval"),
    successorDecisionPacketDigest: digestOf("epoch-3-packet"),
    successorArbitrationDigest: digestOf("epoch-3-arbitration"),
    successorGovernancePublicKeyPem: epoch3Keys.governancePublicKeyPem,
    successorGovernanceKeyId: epoch3Keys.governanceKeyId,
    successorActivationPublicKeyPem: epoch3Keys.activationPublicKeyPem,
    now: later,
  });

  assert.equal(verifyLineage([genesis, epoch2, epoch3], { now: later }).currentEpoch, 3);
  assert.equal(verifyLineage([genesis, epoch2, epoch3], { now: later, enforceTerminalExpiry: true }).currentEpoch, 3);
  assert.throws(
    () => verifyLineage([genesis, epoch2], { now: later, enforceTerminalExpiry: true }),
    /expired/
  );
});

test("candidate apply failure does not retire predecessor", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const active = initializeGovernance({ mode: "genesis" });
  const candidateKeys = createInMemoryGovernanceKeyMaterial();
  const candidate = candidateEvidence();
  const preapproval = signPreapprovalCertificate({
    keyMaterial: active.keyMaterial,
    predecessorEpoch: active.epoch,
    candidate,
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    aiDecision: approveDecision(),
    nonce: "n",
  });
  const { activationNonce } = createActivationChallenge({
    preapprovalEnvelope: preapproval,
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    candidateImageDigest: candidate.candidateImageDigest,
  });
  await completeActivation({
    preapprovalEnvelope: preapproval,
    candidate,
    candidateAttestationToken: "fake.jwt",
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateGovernanceKeyId: candidateKeys.governanceKeyId,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    activationNonce,
    verifyAttestation: async (_jwt, expected) => ({
      dbgstat: "disabled-since-boot",
      swname: "CONFIDENTIAL_SPACE",
      eat_nonce: expected.expectedNonce,
      submods: { container: { image_digest: expected.expectedImageDigest } },
    }),
    arbitrateSuccessor: approveSuccessorArbitration,
  });

  assert.equal(getGovernanceState().status, "activating_successor");
  assert.equal(getGovernanceState().latestRetirementCertificate, null);
  assert.ok(getGovernanceState().pendingSuccessorActivation);
});

test("inactive successor applies only its own activation bundle", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const active = initializeGovernance({ mode: "genesis" });
  const candidateKeys = createInMemoryGovernanceKeyMaterial();
  const candidate = candidateEvidence();
  const preapproval = signPreapprovalCertificate({
    keyMaterial: active.keyMaterial,
    predecessorEpoch: active.epoch,
    candidate,
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    aiDecision: approveDecision(),
    nonce: "n",
  });
  const { activationNonce } = createActivationChallenge({
    preapprovalEnvelope: preapproval,
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    candidateImageDigest: candidate.candidateImageDigest,
  });
  const bundle = await completeActivation({
    preapprovalEnvelope: preapproval,
    candidate,
    candidateAttestationToken: "fake.jwt",
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateGovernanceKeyId: candidateKeys.governanceKeyId,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    activationNonce,
    verifyAttestation: async (_jwt, expected) => ({
      dbgstat: "disabled-since-boot",
      swname: "CONFIDENTIAL_SPACE",
      eat_nonce: expected.expectedNonce,
      submods: { container: { image_digest: expected.expectedImageDigest } },
    }),
    arbitrateSuccessor: approveSuccessorArbitration,
  });

  resetGovernanceForTests({
    status: "inactive",
    epoch: 0,
    imageDigest: candidate.candidateImageDigest,
    keyMaterial: candidateKeys,
    lineage: [],
    latestPreapproval: null,
    latestSuccessorCertificate: null,
    latestRetirementCertificate: null,
    pendingSuccessorActivation: null,
    selfHealingProposals: [],
    pendingActivationChallenges: new Map(),
    transferredState: {},
  });
  await assert.rejects(() => applyActivationBundle({
    ...bundle,
    successorCertificate: {
      ...bundle.successorCertificate,
      payload: {
        ...bundle.successorCertificate.payload,
        candidateImageDigest: digestOf("wrong-image"),
      },
    },
    activationNonce,
  }), /candidate image digest mismatch/);
  const manifest = await applyActivationBundle({ ...bundle, activationNonce });
  assert.equal(manifest.status, "active");
  assert.equal(manifest.governanceKeyId, candidateKeys.governanceKeyId);
});

test("activation hard-vetoes incomplete governance-critical source evidence", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const active = initializeGovernance({ mode: "genesis" });
  const candidateKeys = createInMemoryGovernanceKeyMaterial();
  const candidate = {
    ...candidateEvidence(),
    criticalSourceCompleteness: {
      schema: "femled.tee.governance.critical_source_completeness.v1",
      status: "incomplete",
      requiredFiles: GOVERNANCE_CRITICAL_SOURCE_FILES,
      presentFiles: [],
      missingFiles: GOVERNANCE_CRITICAL_SOURCE_FILES,
    },
  };
  const preapproval = signPreapprovalCertificate({
    keyMaterial: active.keyMaterial,
    predecessorEpoch: active.epoch,
    candidate,
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    aiDecision: approveDecision(),
    nonce: "n",
  });
  const { activationNonce } = createActivationChallenge({
    preapprovalEnvelope: preapproval,
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    candidateImageDigest: candidate.candidateImageDigest,
  });

  await assert.rejects(() => completeActivation({
    preapprovalEnvelope: preapproval,
    candidate,
    candidateAttestationToken: "fake.jwt",
    candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
    candidateGovernanceKeyId: candidateKeys.governanceKeyId,
    candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
    activationNonce,
    verifyAttestation: async (_jwt, expected) => ({
      dbgstat: "disabled-since-boot",
      swname: "CONFIDENTIAL_SPACE",
      eat_nonce: expected.expectedNonce,
      submods: { container: { image_digest: expected.expectedImageDigest } },
    }),
    arbitrateSuccessor: approveSuccessorArbitration,
  }), /governance-critical source evidence is incomplete/);
});

test("self-healing proposals are signed telemetry, not activation authority", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const active = initializeGovernance({ mode: "genesis" });
  recordVertexRetryExhausted({ reason: "simulated outage" });
  const proposal = await issueSelfHealingProposal({
    proposal: {
      type: "model_upgrade",
      problemStatement: "Vertex retries exhausted; consider model policy repair.",
      requestedChange: { file: "src/first-principles-review.js" },
    },
  });
  const manifest = buildGovernanceManifestPayload();
  assert.equal(manifest.status, "active");
  assert.equal(manifest.selfHealing.openProposalDigests[0], proposal.payloadDigest);
  assert.equal(mayServePath("/login"), true);
});

test("self-improvement proposal generation deduplicates equivalent failures", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  recordVertexRetryExhausted({ reason: "simulated outage" });

  const now = new Date();
  const first = await evaluateSelfImprovementOnce({ now });
  const second = await evaluateSelfImprovementOnce({ now: new Date(now.getTime() + 60_000) });
  const manifest = buildGovernanceManifestPayload();

  assert.ok(first?.proposalEnvelope);
  assert.equal(second, null);
  assert.equal(manifest.selfHealing.openProposalDigests.length, 1);
  assert.equal(manifest.selfHealing.repairJobs.openJobs.length, 1);
});

test("model policy upgrade self-healing is inactive until active governance", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance();
  const result = await evaluateSelfImprovementOnce({
    now: new Date(),
    modelPolicyUpgradeOptions: passingModelUpgradeOptions(),
  });
  assert.equal(result, null);
});

test("model policy upgrade self-healing respects scan interval", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  const current = initializeGovernance({ mode: "genesis" });
  const now = new Date("2026-05-08T00:00:00Z");
  current.modelPolicySupervisor.lastScanAt = now.toISOString();
  let discoveryCalls = 0;
  const result = await evaluateSelfImprovementOnce({
    now: new Date(now.getTime() + 60_000),
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 24 * 60 * 60 * 1000,
      discoverModelCandidates: async () => {
        discoveryCalls += 1;
        return [strongerCatalogCandidate()];
      },
      probeModelCandidate: async (model) => ({ status: "passed", model, responseDigest: digestOf(`probe:${model}`) }),
    },
  });
  assert.equal(result, null);
  assert.equal(discoveryCalls, 0);
});

test("model policy upgrade self-healing proposes highest passing discovered model once", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  const now = new Date();
  const first = await evaluateSelfImprovementOnce({
    now,
    modelPolicyUpgradeOptions: passingModelUpgradeOptions(),
  });
  const second = await evaluateSelfImprovementOnce({
    now: new Date(now.getTime() + 60 * 60 * 1000),
    modelPolicyUpgradeOptions: passingModelUpgradeOptions(),
  });
  const manifest = buildGovernanceManifestPayload();
  const proposal = first.proposalEnvelope.payload;

  assert.ok(first?.proposalEnvelope);
  assert.equal(second, null);
  assert.equal(proposal.type, "model_policy_upgrade");
  assert.equal(proposal.requestedChange.targetModel, "gemini-9.0-pro");
  assert.deepEqual(proposal.requestedChange.requiredSourcePaths, [
    "src/first-principles-review.js",
    "repair-worker/repair-worker-run.py",
  ]);
  assert.equal(
    proposal.requestedChange.instructions.some((instruction) =>
      instruction.includes("repair-worker/repair-worker-run.py")
    ),
    true
  );
  assert.match(proposal.requestedChange.modelProbeDigest, /^sha256:/);
  assert.match(proposal.requestedChange.modelPolicyDiffDigest, /^sha256:/);
  assert.equal(manifest.selfHealing.openProposalDigests.length, 1);
  assert.equal(manifest.selfHealing.modelPolicySupervisor.lastCandidateModel, "gemini-9.0-pro");
  assert.equal(manifest.selfHealing.repairJobs.openJobs.length, 1);
});

test("model policy supervisor records catalog errors without exposing raw messages", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  const current = initializeGovernance({ mode: "genesis" });
  const now = new Date("2026-05-08T00:00:00Z");

  await assert.rejects(() => evaluateModelPolicyUpgradeOpportunity({
    current,
    now,
    discoverModelCandidates: async () => {
      throw new Error("catalog secret detail");
    },
  }), /catalog secret detail/);

  assert.equal(current.modelPolicySupervisor.lastEvaluationAt, now.toISOString());
  assert.equal(current.modelPolicySupervisor.lastScanStartedAt, now.toISOString());
  assert.equal(current.modelPolicySupervisor.lastScanAt, null);
  assert.equal(current.modelPolicySupervisor.lastScanError.stage, "catalog_discovery");
  assert.match(current.modelPolicySupervisor.lastScanError.messageDigest, /^sha256:/);
  assert.equal(JSON.stringify(current.modelPolicySupervisor.lastScanError).includes("catalog secret detail"), false);
});

test("model policy supervisor times out hung probes and completes scan evidence", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  const current = initializeGovernance({ mode: "genesis" });
  const now = new Date("2026-05-08T00:00:00Z");

  const result = await evaluateModelPolicyUpgradeOpportunity({
    current,
    now,
    probeTimeoutMs: 1,
    discoverModelCandidates: async () => [strongerCatalogCandidate()],
    probeModelCandidate: async () => new Promise(() => {}),
  });

  assert.equal(result.proposal, null);
  assert.equal(current.modelPolicySupervisor.lastScanAt, now.toISOString());
  assert.equal(current.modelPolicySupervisor.lastCandidateModel, null);
  assert.equal(result.evidence.probeResults[0].status, "failed");
  assert.match(result.evidence.probeResults[0].reason, /ETIMEDOUT/);
});

test("privacy-safe operational health never exposes raw errors or tenant identifiers", () => {
  resetGovernanceMonitorForTests();
  const tenantId = "019a8314-3e69-7bb1-b8ee-19bc54723979";
  const routeDigest = digestOf("tenant-route");
  const secretError = new Error(`deposit failed for ${tenantId} and alice@example.com`);

  recordSelfImprovement({ status: "failed", error: secretError });
  recordManifestAttestation({ surface: "governance", status: "failed", error: secretError });
  recordTokenDeposit({ routeDigest, status: "failed", httpStatus: 502, error: secretError });
  recordTenantRouteLookup({ status: "failed", lookupDigest: digestOf(tenantId) });
  recordRouteProof({ routeDigest, status: "failed", error: Object.assign(secretError, { code: "ROUTE_PROOF_FAILED" }) });
  recordDeployWebhook({ repoDigest: digestOf("private-repo-name"), status: "failed", error: Object.assign(new Error("missing repo private-repo-name"), { code: "MISSING_ROUTE" }) });

  const health = buildHealthSnapshot({ governanceStatus: "active" });
  const text = JSON.stringify(health);

  assert.equal(text.includes(tenantId), false);
  assert.equal(text.includes("alice@example.com"), false);
  assert.equal(text.includes("private-repo-name"), false);
  assert.equal(health.operational.selfImprovement.lastSelfImprovementError.category, "unknown");
  assert.equal(health.operational.manifestAttestation.lastManifestAttestationError.category, "unknown");
  assert.equal(health.operational.tenantContract.routes.some((route) => route.routeDigest === routeDigest), true);
  assert.equal(health.operational.tenantContract.routes.find((route) => route.routeDigest === routeDigest).tokenDepositFailureRate, 1);
  assert.equal(health.operational.tenantContract.tokenDepositFailures, 1);
  assert.equal(health.operational.tenantContract.tenantRouteLookupFailures, 1);
  assert.equal(health.operational.tenantContract.routeProofFailures, 1);
  assert.equal(health.operational.tenantContract.deployWebhookFailures, 1);
});

test("repair job manifest exposes stale age summary without callback tokens", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  const proposal = await issueSelfHealingProposal({
    proposal: {
      type: "route_registry_repair",
      problemStatement: "route registry health signal is unresolved",
      requestedChange: { surface: "route-registry" },
    },
    now: new Date("2026-05-08T00:00:00Z"),
  });
  createRepairJobForProposal({
    proposalEnvelope: proposal,
    healthSnapshot: buildHealthSnapshot({ governanceStatus: "active" }),
    now: new Date(Date.now() - 3 * 60 * 60 * 1000),
  });

  const manifest = buildGovernanceManifestPayload();
  const jobs = manifest.selfHealing.repairJobs;
  assert.equal(jobs.summary.staleOpenJobCount, 1);
  assert.ok(jobs.summary.oldestOpenJobAgeMs >= 2 * 60 * 60 * 1000);
  assert.equal(JSON.stringify(jobs).includes('"callbackToken":'), false);
});

test("single token deposit failure does not trigger tenant contract repair", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  recordTokenDeposit({ routeDigest: digestOf("tenant-route"), status: "failed", httpStatus: 502 });

  const result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });

  const health = buildHealthSnapshot({ governanceStatus: "active" });
  assert.equal(result, null);
  assert.equal(health.unresolvedFailures.tokenDeposit, false);
  assert.equal(health.operational.tenantContract.tokenDepositFailures, 1);
});

test("thresholded token deposit failures trigger tenant contract repair without sensitive output", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  const routeDigest = digestOf("tenant-route");
  const tenantId = "019a8314-3e69-7bb1-b8ee-19bc54723979";
  for (let i = 0; i < 3; i += 1) {
    recordTokenDeposit({
      routeDigest,
      status: "failed",
      error: new Error(`tenant ${tenantId} token deposit failed for alice@example.com`),
    });
  }

  const result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });
  const text = JSON.stringify(result);

  assert.equal(result.proposalEnvelope.payload.type, "tenant_contract_repair");
  assert.equal(result.proposalEnvelope.payload.requestedChange.surface, "tenant-contract");
  assert.equal(text.includes(tenantId), false);
  assert.equal(text.includes("alice@example.com"), false);
  assert.equal(result.health.unresolvedFailures.tokenDeposit, true);
});

test("manifest attestation failure triggers repair with generic error category", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  recordManifestAttestation({
    surface: "governance",
    status: "failed",
    error: new Error("manifest failed for alice@example.com"),
  });

  const result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });
  const text = JSON.stringify(result);

  assert.equal(result.proposalEnvelope.payload.type, "manifest_attestation_repair");
  assert.equal(result.proposalEnvelope.payload.requestedChange.surface, "manifest-attestation");
  assert.equal(text.includes("alice@example.com"), false);
  assert.equal(result.health.operational.unresolved.manifestAttestation.lastError.category, "unknown");
});

test("stale repair job triggers repair worker repair", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  const proposal = await issueSelfHealingProposal({
    proposal: {
      type: "route_registry_repair",
      problemStatement: "route registry health signal is unresolved",
      requestedChange: { surface: "route-registry" },
    },
    now: new Date("2026-05-08T00:00:00Z"),
  });
  createRepairJobForProposal({
    proposalEnvelope: proposal,
    healthSnapshot: buildHealthSnapshot({ governanceStatus: "active" }),
    now: new Date(Date.now() - 3 * 60 * 60 * 1000),
  });

  const result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });

  assert.equal(result.proposalEnvelope.payload.type, "repair_worker_repair");
  assert.equal(result.proposalEnvelope.payload.requestedChange.surface, "repair-worker");
  assert.equal(result.health.unresolvedFailures.staleRepairJobs, true);
});

test("missing route lookup is digest-only and thresholded", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  const tenantId = "019a8314-3e69-7bb1-b8ee-19bc54723979";
  const lookupDigest = digestOf(tenantId);
  recordTenantRouteLookup({ status: "failed", lookupDigest });
  recordTenantRouteLookup({ status: "failed", lookupDigest });
  let result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });
  assert.equal(result, null);

  recordTenantRouteLookup({ status: "failed", lookupDigest });
  result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });
  const text = JSON.stringify(result);

  assert.equal(result.proposalEnvelope.payload.type, "tenant_contract_repair");
  assert.equal(result.health.unresolvedFailures.tenantRouteLookup, true);
  assert.equal(text.includes(tenantId), false);
  assert.equal(text.includes(lookupDigest), true);
});

test("route proof failure triggers tenant contract repair immediately", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  const routeDigest = digestOf("route-proof");
  recordRouteProof({
    routeDigest,
    status: "failed",
    error: Object.assign(new Error("route proof failure for alice@example.com"), { code: "ROUTE_PROOF_FAILED" }),
  });

  const result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });
  const text = JSON.stringify(result);

  assert.equal(result.proposalEnvelope.payload.type, "tenant_contract_repair");
  assert.equal(result.health.unresolvedFailures.routeProof, true);
  assert.equal(text.includes("alice@example.com"), false);
  assert.equal(text.includes(routeDigest), true);
});

test("deploy webhook failures are thresholded before repair", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  const routeDigest = digestOf("deploy-webhook");
  const repoName = "private-repo-name";
  recordDeployWebhook({ routeDigest, status: "failed", httpStatus: 502, error: new Error(repoName) });

  let result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });
  assert.equal(result, null);

  recordDeployWebhook({ routeDigest, status: "failed", httpStatus: 502, error: new Error(repoName) });
  result = await evaluateSelfImprovementOnce({
    modelPolicyUpgradeOptions: {
      scanIntervalMs: 0,
      discoverModelCandidates: async () => [],
    },
  });
  const text = JSON.stringify(result);

  assert.equal(result.proposalEnvelope.payload.type, "deploy_webhook_repair");
  assert.equal(result.proposalEnvelope.payload.requestedChange.surface, "deploy-webhook");
  assert.equal(result.health.unresolvedFailures.deployWebhook, true);
  assert.equal(text.includes(repoName), false);
});

test("operational successes clear prior unresolved failure counters", () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  const routeDigest = digestOf("recovering-route");

  recordSelfImprovement({ status: "failed", error: new Error("first") });
  recordSelfImprovement({ status: "failed", error: new Error("second") });
  recordRepairLaunch({ status: "failed", error: new Error("job missing") });
  recordManifestAttestation({ surface: "policy", status: "failed", error: new Error("stale") });
  recordDeployWebhook({ routeDigest, status: "failed", httpStatus: 500 });
  recordDeployWebhook({ routeDigest, status: "failed", httpStatus: 500 });

  let health = buildHealthSnapshot({ governanceStatus: "active" });
  assert.equal(health.unresolvedFailures.selfImprovement, true);
  assert.equal(health.unresolvedFailures.repairLaunch, true);
  assert.equal(health.unresolvedFailures.manifestAttestation, true);
  assert.equal(health.unresolvedFailures.deployWebhook, true);

  recordSelfImprovement({ status: "success" });
  recordRepairLaunch({ status: "success", launchedCount: 1 });
  recordManifestAttestation({ surface: "policy", status: "success" });
  recordDeployWebhook({ routeDigest, status: "success", httpStatus: 200 });

  health = buildHealthSnapshot({ governanceStatus: "active" });
  assert.equal(health.unresolvedFailures.selfImprovement, false);
  assert.equal(health.unresolvedFailures.repairLaunch, false);
  assert.equal(health.unresolvedFailures.manifestAttestation, false);
  assert.equal(health.unresolvedFailures.deployWebhook, false);
  assert.equal(health.counters.selfImprovementFailures, 0);
  assert.equal(health.counters.repairLaunchFailures, 0);
  assert.equal(health.counters.manifestAttestationFailures, 0);
  assert.equal(health.counters.deployWebhookFailures, 0);
});

test("repair worker contract validates artifacts but does not approve candidates", () => {
  const keys = createInMemoryGovernanceKeyMaterial();
  const proposal = signPreapprovalLikeProposal(keys);
  const prompt = buildRepairPromptEnvelope({
    proposalEnvelope: proposal,
    healthSnapshotDigest: digestOf("health"),
    requestedChange: { modelPolicy: "candidate" },
  });
  assert.equal(prompt.authorityReminder.includes("cannot approve"), true);
  const modelUpgradePrompt = buildRepairPromptEnvelope({
    proposalEnvelope: proposal,
    healthSnapshotDigest: digestOf("health"),
    requestedChange: { schema: "femled.tee.model_policy.upgrade_request.v1" },
  });
  assert.equal(modelUpgradePrompt.modelPolicyUpgradeReminder.includes("repair worker default model"), true);
  const artifact = validateRepairArtifactEnvelope({
    schema: "femled.tee.repair_worker.artifact_envelope.v1",
    runId: "run-1",
    proposalDigest: proposal.payloadDigest,
    promptDigest: digestOf("prompt"),
    branch: "repair/model-policy",
    prUrl: "https://github.com/FemLed/auth-broker-tee/pull/1",
    sourceBundleDigest: digestOf("source"),
    buildSummaryDigest: digestOf("build"),
    testSummaryDigest: digestOf("test"),
    modelProbeDigest: digestOf("model-probe"),
    modelCatalogEvidenceDigest: digestOf("model-catalog"),
    modelPolicyDiffDigest: digestOf("model-policy-diff"),
  }, { expectedProposalDigest: proposal.payloadDigest });
  assert.match(artifact.artifactDigest, /^sha256:/);
  assert.equal(artifact.modelProbeDigest, digestOf("model-probe"));
});

test("repair callback payloads need per-job token and remain inert", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  recordVertexRetryExhausted({ reason: "simulated outage" });
  await evaluateSelfImprovementOnce({ now: new Date() });
  const [job] = getPendingRepairJobsForLaunch();
  const artifact = {
    schema: "femled.tee.repair_worker.artifact_envelope.v1",
    runId: "run-1",
    proposalDigest: job.proposalDigest,
    promptDigest: job.promptDigest,
    sourceBundleDigest: digestOf("source"),
    buildSummaryDigest: digestOf("build"),
    testSummaryDigest: digestOf("test"),
  };

  assert.throws(() => recordRepairArtifact(artifact, { callbackToken: "wrong" }), /callback token/);
  const recorded = recordRepairArtifact(artifact, { callbackToken: job.callbackToken });
  assert.equal(recorded.status.payload.status, "finished");
  assert.equal(getGovernanceState().status, "active");
});

test("repair investigation artifacts remain inert evidence", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  initializeGovernance({ mode: "genesis" });
  recordVertexRetryExhausted({ reason: "simulated outage" });
  await evaluateSelfImprovementOnce({ now: new Date() });
  const [job] = getPendingRepairJobsForLaunch();
  const investigation = {
    schema: "femled.tee.repair_worker.evidence_investigation.v1",
    runId: "run-1",
    proposalDigest: job.proposalDigest,
    promptDigest: job.promptDigest,
    questionDigest: digestOf("question"),
    answerDigest: digestOf("answer"),
    evidenceDigest: digestOf("evidence"),
  };
  const recorded = recordRepairArtifact(investigation, { callbackToken: job.callbackToken });
  assert.equal(recorded.status.payload.status, "investigation_recorded");
  assert.equal(recorded.investigationArtifactDigests.length, 1);
  assert.equal(getGovernanceState().status, "active");
});

test("candidate inspection can require complete governance-critical source", async () => {
  const candidate = await inspectCandidateImageEvidence({
    candidateImageDigest: IMAGE_DIGEST,
    manifest: { schemaVersion: 2 },
    manifestDigest: IMAGE_DIGEST,
    sourceBundle: {
      requireCompleteGovernanceCriticalSource: true,
      files: {
        "src/server.js": "export function route() {}",
      },
    },
  });
  assert.equal(candidate.criticalSourceCompleteness.status, "incomplete");
  assert.equal(candidate.hardCheckResults.status, "failed");
  assert.match(candidate.hardCheckResults.failures.join("\n"), /governance-critical files/);
});

test("candidate inspection passes complete governance-critical source", async () => {
  const files = Object.fromEntries(
    GOVERNANCE_CRITICAL_SOURCE_FILES.map((file) => [file, file.endsWith(".go") ? "package main\n" : "export const ok = true;"])
  );
  const candidate = await inspectCandidateImageEvidence({
    candidateImageDigest: IMAGE_DIGEST,
    manifest: { schemaVersion: 2 },
    manifestDigest: IMAGE_DIGEST,
    sourceBundle: {
      requireCompleteGovernanceCriticalSource: true,
      files,
    },
  });
  assert.equal(candidate.criticalSourceCompleteness.status, "complete");
  assert.equal(candidate.hardCheckResults.status, "passed");
});

test("repair worker launch overrides never include GitHub write tokens", () => {
  const overrides = buildRepairJobOverrides({
    jobId: "repair:test",
    proposalDigest: digestOf("proposal"),
    promptEnvelope: { task: "build evidence only" },
    promptDigest: digestOf("prompt"),
    callbackToken: "callback-token",
  });
  const envNames = overrides.containerOverrides[0].env.map((item) => item.name);
  assert.equal(envNames.includes("TEE_REPAIR_GITHUB_TOKEN"), false);
  assert.equal(envNames.includes("TEE_REPAIR_CALLBACK_TOKEN"), true);
});

test("self-healing candidates require a live predecessor-signed proposal", async () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  initializeGovernance({ mode: "genesis" });
  await assert.rejects(
    () => issuePreapprovalCertificate({
      candidate: { ...candidateEvidence(), selfHealingProposalDigest: digestOf("missing-proposal") },
      hardCheckResults: { status: "passed", failures: [], warnings: [] },
      aiDecision: approveDecision(),
      nonce: "n",
    }),
    /self-healing proposal/
  );
});

test("preapproval binds candidate source structure digest", () => {
  const keys = createInMemoryGovernanceKeyMaterial();
  const candidate = {
    ...candidateEvidence(),
    candidateSourceStructureDigest: digestOf("source-structure"),
  };
  const preapproval = signPreapprovalCertificate({
    keyMaterial: keys,
    predecessorEpoch: 1,
    candidate,
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    aiDecision: approveDecision(),
    nonce: "n",
  });
  const payload = verifyGovernanceEnvelope(preapproval, keys.governancePublicKeyPem);
  assert.equal(payload.candidateSourceStructureDigest, candidate.candidateSourceStructureDigest);
  assert.throws(
    () => assertPreapprovalMatchesCandidate(payload, {
      ...candidate,
      candidateSourceStructureDigest: digestOf("different-structure"),
    }),
    /candidateSourceStructureDigest mismatch/
  );
});

test("encrypted transfer cannot decrypt with the wrong successor key", async () => {
  const activeKeys = createInMemoryGovernanceKeyMaterial();
  const intended = createInMemoryGovernanceKeyMaterial();
  const wrong = createInMemoryGovernanceKeyMaterial();
  const aad = { successorPayloadDigest: digestOf("successor"), activationNonce: "nonce" };
  const envelope = activeKeys.encryptStateFor(intended.activationPublicKeyPem, { secret: "state" }, aad);
  assert.throws(() => wrong.decryptState(envelope, aad));
  assert.deepEqual(intended.decryptState(envelope, aad), { secret: "state" });
});

test("governance preapproval rejects missing OIDC before body inspection", async () => {
  resetGovernanceRouteSecurityForTests();
  const req = governanceRequest({
    body: "not json",
    authorization: "",
    remoteAddress: "198.51.100.10",
  });
  const res = createMockResponse();

  await handleGovernancePreapproval(req, res);

  assert.equal(res.statusCode, 401);
  assert.match(JSON.parse(res.body).error, /Missing GitHub Actions OIDC bearer token/);
});

test("governance challenge rejects invalid OIDC claims", async () => {
  resetGovernanceRouteSecurityForTests();
  setGovernanceOidcVerifierForTests(async () => {
    throw new Error("aud must be https://oauth-tee.femled.ai/governance");
  });
  const req = governanceRequest({
    body: {
      purpose: "governance.preapprove",
      requestDigest: digestOf("request"),
    },
    authorization: "Bearer wrong-audience",
    remoteAddress: "198.51.100.11",
  });
  const res = createMockResponse();

  await handleGovernanceChallenge(req, res);

  assert.equal(res.statusCode, 401);
  assert.match(JSON.parse(res.body).error, /aud must be/);
});

test("governance preapproval challenge is request-bound, actor-bound, expiring, and one-time use", async () => {
  resetGovernanceRouteSecurityForTests();
  const baseNow = new Date("2026-05-05T00:00:00Z");
  setGovernanceRouteNowForTests(() => baseNow);
  setGovernanceOidcVerifierForTests(mockGovernanceOidcVerifier);
  const preapprovalRequest = {
    candidateImageDigest: IMAGE_DIGEST,
    sourceBundle: preapprovalSourceBundle(),
  };
  const requestDigest = digestOf(preapprovalRequest);

  const challenge = await requestGovernanceChallenge({ requestDigest, authorization: "Bearer valid-1" });

  const wrongActor = createMockResponse();
  await handleGovernancePreapproval(governanceRequest({
    body: { ...preapprovalRequest, governanceChallenge: challenge },
    authorization: "Bearer valid-2",
    remoteAddress: "198.51.100.12",
  }), wrongActor);
  assert.equal(wrongActor.statusCode, 401);
  assert.match(JSON.parse(wrongActor.body).error, /caller mismatch/);

  const accepted = createMockResponse();
  await handleGovernancePreapproval(governanceRequest({
    body: { ...preapprovalRequest, governanceChallenge: challenge },
    authorization: "Bearer valid-1",
    remoteAddress: "198.51.100.12",
  }), accepted);
  assert.equal(accepted.statusCode, 422);
  assert.equal(JSON.parse(accepted.body).decision, "REQUEST_CHANGES");

  const replay = createMockResponse();
  await handleGovernancePreapproval(governanceRequest({
    body: { ...preapprovalRequest, governanceChallenge: challenge },
    authorization: "Bearer valid-1",
    remoteAddress: "198.51.100.12",
  }), replay);
  assert.equal(replay.statusCode, 401);
  assert.match(JSON.parse(replay.body).error, /Invalid or expired/);

  const digestMismatchChallenge = await requestGovernanceChallenge({ requestDigest, authorization: "Bearer valid-1" });
  const digestMismatch = createMockResponse();
  await handleGovernancePreapproval(governanceRequest({
    body: {
      candidateImageDigest: digestOf("different-candidate"),
      sourceBundle: preapprovalSourceBundle(),
      governanceChallenge: digestMismatchChallenge,
    },
    authorization: "Bearer valid-1",
    remoteAddress: "198.51.100.13",
  }), digestMismatch);
  assert.equal(digestMismatch.statusCode, 401);
  assert.match(JSON.parse(digestMismatch.body).error, /request digest mismatch/);

  const expiringChallenge = await requestGovernanceChallenge({ requestDigest, authorization: "Bearer valid-1" });
  setGovernanceRouteNowForTests(() => new Date(baseNow.getTime() + 6 * 60 * 1000));
  const expired = createMockResponse();
  await handleGovernancePreapproval(governanceRequest({
    body: { ...preapprovalRequest, governanceChallenge: expiringChallenge },
    authorization: "Bearer valid-1",
    remoteAddress: "198.51.100.14",
  }), expired);
  assert.equal(expired.statusCode, 401);
  assert.match(JSON.parse(expired.body).error, /Invalid or expired/);
});

test("governance preapproval source provenance must match OIDC run and SHA", async () => {
  resetGovernanceRouteSecurityForTests();
  setGovernanceOidcVerifierForTests(mockGovernanceOidcVerifier);
  const preapprovalRequest = {
    candidateImageDigest: IMAGE_DIGEST,
    sourceBundle: preapprovalSourceBundle({ headSha: "b".repeat(40) }),
  };
  const challenge = await requestGovernanceChallenge({
    requestDigest: digestOf(preapprovalRequest),
    authorization: "Bearer valid-1",
  });
  const res = createMockResponse();

  await handleGovernancePreapproval(governanceRequest({
    body: { ...preapprovalRequest, governanceChallenge: challenge },
    authorization: "Bearer valid-1",
    remoteAddress: "198.51.100.17",
  }), res);

  assert.equal(res.statusCode, 400);
  assert.match(JSON.parse(res.body).error, /headSha must match GitHub OIDC sha/);
});

test("governance challenge route applies authenticated rate limits", async () => {
  resetGovernanceRouteSecurityForTests();
  setGovernanceRouteNowForTests(() => new Date("2026-05-05T00:00:00Z"));
  setGovernanceOidcVerifierForTests(mockGovernanceOidcVerifier);
  let last;
  for (let i = 0; i < 31; i += 1) {
    last = createMockResponse();
    await handleGovernanceChallenge(governanceRequest({
      body: {
        purpose: "governance.preapprove",
        requestDigest: digestOf(`request-${i}`),
      },
      authorization: "Bearer valid-1",
      remoteAddress: "198.51.100.15",
    }), last);
  }

  assert.equal(last.statusCode, 429);
  assert.match(JSON.parse(last.body).error, /rate limit exceeded/);
});

test("authorized governance activation offer still creates a nonce-bound challenge", async () => {
  resetGovernanceRouteSecurityForTests();
  resetGovernanceForTests();
  setGovernanceOidcVerifierForTests(mockGovernanceOidcVerifier);
  initializeGovernance({ mode: "genesis", now: new Date("2026-05-05T00:00:00Z") });
  const candidateKeys = createInMemoryGovernanceKeyMaterial();
  const candidate = candidateEvidence();
  const preapprovalEnvelope = await issuePreapprovalCertificate({
    candidate,
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    aiDecision: approveDecision(),
    aiResponseDigest: digestOf("ai-response"),
    nonce: "preapproval-nonce",
    challengeDigest: digestOf("challenge"),
    requestDigest: digestOf("request"),
    authorizedCallerDigest: digestOf("caller"),
    authorizedWorkflowRef: "FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master",
    authorizedRunId: "1001",
  });

  const res = createMockResponse();
  await handleActivationOffer(governanceRequest({
    body: {
      preapprovalEnvelope,
      candidateGovernancePublicKeyPem: candidateKeys.governancePublicKeyPem,
      candidateActivationPublicKeyPem: candidateKeys.activationPublicKeyPem,
      candidateImageDigest: candidate.candidateImageDigest,
    },
    authorization: "Bearer valid-1",
    remoteAddress: "198.51.100.16",
  }), res);

  assert.equal(res.statusCode, 200);
  assert.match(JSON.parse(res.body).activationNonce, /^sha256:/);
});

test("tenant admission requires tenant-signed registration proof instead of GitHub OIDC", async () => {
  resetGovernanceRouteSecurityForTests();
  resetGovernanceForTests();
  setGovernanceRouteNowForTests(() => new Date("2026-05-05T00:05:00Z"));
  initializeGovernance({ mode: "genesis", now: new Date("2026-05-05T00:00:00Z") });
  const tenantKeys = createInMemoryGovernanceKeyMaterial();

  const missingProof = createMockResponse();
  await handleTenantAdmission(governanceRequest({
    body: tenantAdmissionRequest({ tenantKeys }),
    authorization: "Bearer valid-1",
    remoteAddress: "198.51.100.18",
  }), missingProof);
  assert.equal(missingProof.statusCode, 400);
  assert.match(JSON.parse(missingProof.body).error, /registrationEnvelope/);

  const request = tenantAdmissionRequest({ tenantKeys });
  request.registrationEnvelope = signTenantRegistration({ request, tenantKeys });
  const admitted = createMockResponse();
  await handleTenantAdmission(governanceRequest({
    body: request,
    authorization: "",
    remoteAddress: "198.51.100.18",
  }), admitted);

  assert.equal(admitted.statusCode, 200);
  const body = JSON.parse(admitted.body);
  assert.equal(body.authority, "tenant_signed_registration_and_active_tee_governance_key");
  assert.equal(body.admission.payload.registrationProofDigest, body.registrationProofDigest);
});

test("tenant admission rejects registration signed by the wrong tenant key", async () => {
  resetGovernanceRouteSecurityForTests();
  resetGovernanceForTests();
  setGovernanceRouteNowForTests(() => new Date("2026-05-05T00:05:00Z"));
  initializeGovernance({ mode: "genesis", now: new Date("2026-05-05T00:00:00Z") });
  const tenantKeys = createInMemoryGovernanceKeyMaterial();
  const wrongKeys = createInMemoryGovernanceKeyMaterial();
  const request = tenantAdmissionRequest({ tenantKeys });
  request.registrationEnvelope = signTenantRegistration({ request, tenantKeys: wrongKeys });

  const res = createMockResponse();
  await handleTenantAdmission(governanceRequest({
    body: request,
    authorization: "",
    remoteAddress: "198.51.100.19",
  }), res);

  assert.equal(res.statusCode, 400);
  assert.match(JSON.parse(res.body).error, /signature key must be one of tenantRouteSigningKeys|signature verification failed/);
});

async function requestGovernanceChallenge({ requestDigest, authorization }) {
  const res = createMockResponse();
  await handleGovernanceChallenge(governanceRequest({
    body: {
      purpose: "governance.preapprove",
      requestDigest,
    },
    authorization,
    remoteAddress: "198.51.100.12",
  }), res);
  assert.equal(res.statusCode, 200);
  return JSON.parse(res.body).challenge;
}

async function mockGovernanceOidcVerifier(authHeader, expected = {}) {
  if (!authHeader?.startsWith("Bearer valid-")) {
    throw new Error("invalid test OIDC token");
  }
  const suffix = authHeader.slice("Bearer valid-".length);
  return {
    iss: "https://token.actions.githubusercontent.com",
    aud: expected.audience,
    sub: `repo:FemLed/auth-broker-tee:ref:refs/heads/master:actor:${suffix}`,
    repository: "FemLed/auth-broker-tee",
    job_workflow_ref: expected.workflowRefs?.[0],
    event_name: "push",
    run_id: `100${suffix}`,
    actor: `actor-${suffix}`,
    ref: "refs/heads/master",
    sha: "a".repeat(40),
  };
}

function governanceRequest({ body, authorization = "Bearer valid-1", remoteAddress = "198.51.100.1" } = {}) {
  const chunks = typeof body === "string" ? [body] : [JSON.stringify(body || {})];
  const req = Readable.from(chunks);
  req.method = "POST";
  req.headers = authorization ? { authorization } : {};
  req.socket = { remoteAddress };
  return req;
}

function createMockResponse() {
  return {
    statusCode: 0,
    headers: {},
    body: "",
    writeHead(status, headers = {}) {
      this.statusCode = status;
      this.headers = headers;
    },
    end(chunk = "") {
      this.body += chunk;
    },
  };
}

function preapprovalSourceBundle({ workflowRunId = "1001", headSha = "a".repeat(40) } = {}) {
  return {
    workflowRunId,
    headSha,
    provenanceDigest: sha256Digest(canonicalStringify({ workflowRunId, headSha })),
  };
}

function tenantAdmissionRequest({ tenantKeys }) {
  return {
    tenant: "019a8314-3e69-7bb1-b8ee-19bc54723979",
    tenantRouteSigningKeys: [
      {
        keyId: tenantKeys.governanceKeyId,
        alg: "Ed25519",
        publicKeyPem: tenantKeys.governancePublicKeyPem,
      },
    ],
    minRouteVersion: 2,
    allowedApiHosts: ["api-019a8314-3e69-7bb1-b8ee-19bc54723979.femled.ai"],
    allowedAppHosts: ["app-019a8314-3e69-7bb1-b8ee-19bc54723979.femled.ai"],
    allowedBrokerAudiences: ["https://oauth-tee.femled.ai"],
  };
}

function signTenantRegistration({ request, tenantKeys }) {
  const payload = {
    schema: "femled.auth_broker.tenant_registration.v1",
    tenant: request.tenant,
    tenantRouteSigningKeys: request.tenantRouteSigningKeys,
    minRouteVersion: request.minRouteVersion,
    allowedApiHosts: request.allowedApiHosts,
    allowedAppHosts: request.allowedAppHosts,
    allowedBrokerAudiences: request.allowedBrokerAudiences,
    issuedAt: "2026-05-05T00:00:00Z",
    expiresAt: "2026-05-05T00:10:00Z",
  };
  return {
    payload,
    payloadDigest: sha256Digest(canonicalStringify(payload)),
    signature: {
      alg: "Ed25519",
      keyId: tenantKeys.governanceKeyId,
      sig: tenantKeys.sign(payload),
    },
  };
}

function candidateEvidence() {
  return {
    candidateImageDigest: IMAGE_DIGEST,
    candidateImageReference: "example.invalid/repo/image@sha256:abc",
    candidateSourceTreeDigest: digestOf("source-tree"),
    candidateFilesystemDigest: digestOf("filesystem"),
    candidatePolicyManifestDigest: digestOf("policy"),
    candidatePromptDigest: digestOf("prompt"),
    candidateRouteTrustAnchorsDigest: digestOf("routes"),
    candidateChangedFiles: ["src/server.js"],
    hardCheckResults: { status: "passed", failures: [], warnings: [] },
    criticalSourceCompleteness: {
      schema: "femled.tee.governance.critical_source_completeness.v1",
      status: "complete",
      requiredFiles: GOVERNANCE_CRITICAL_SOURCE_FILES,
      presentFiles: GOVERNANCE_CRITICAL_SOURCE_FILES,
      missingFiles: [],
    },
  };
}

function approveDecision() {
  return {
    decision: "APPROVE",
    reasoning: "Strengthens self-governance.",
    violatedPrinciples: [],
    remediation: [],
    governanceRiskLevel: "low",
    stateTransferRisk: "low",
    imageInspectionSummary: "Exact digest reviewed.",
    mustNotApproveIf: [],
  };
}

function digestOf(value) {
  return sha256Digest(canonicalStringify(value));
}

function passingModelUpgradeOptions() {
  return {
    scanIntervalMs: 0,
    discoverModelCandidates: async () => [
      {
        model: "gemini-8.0-pro",
        rank: 8100,
        releaseChannel: "catalog",
        launchStage: "GA",
        catalogDigest: digestOf("catalog:gemini-8.0-pro"),
      },
      strongerCatalogCandidate(),
    ],
    probeModelCandidate: async (model) => ({
      status: "passed",
      model,
      responseDigest: digestOf(`probe:${model}`),
    }),
  };
}

function strongerCatalogCandidate() {
  return {
    model: "gemini-9.0-pro",
    rank: 9100,
    releaseChannel: "catalog",
    launchStage: "GA",
    catalogDigest: digestOf("catalog:gemini-9.0-pro"),
  };
}

function genesisBootstrapRequest(targetImageDigest) {
  return {
    repository: "FemLed/auth-broker-tee",
    eventName: "push",
    headSha: "b".repeat(40),
    workflowRunId: "123",
    changedFiles: ["GENESIS_BOOTSTRAP.md"],
    diff: `Authorize self-governance genesis bootstrap for target image ${targetImageDigest}. This is the first self-governing TEE deployment.`,
  };
}

function genesisBootstrapResponse(request, { decision, expiresAt }) {
  const payload = {
    schema: "femled.first_principles.adjudication.v1",
    repository: request.repository,
    eventName: request.eventName,
    headSha: request.headSha,
    workflowRunId: request.workflowRunId,
    nonce: "nonce",
    changedFilesDigest: sha256Digest(canonicalStringify(request.changedFiles)),
    diffDigest: sha256Digest(request.diff),
    decision,
    reasoning: "Genesis bootstrap aligns with first principles.",
    violatedPrinciples: [],
    remediation: [],
    expiresAt,
  };
  return {
    payload,
    payloadDigest: sha256Digest(canonicalStringify(payload)),
    attestationToken: "fake.jwt",
  };
}

async function trustedBootstrapAttestation(_jwt, expected) {
  return {
    dbgstat: "disabled-since-boot",
    swname: "CONFIDENTIAL_SPACE",
    eat_nonce: expected.expectedNonce,
    submods: {
      container: {
        image_digest: "sha256:a3b34e462346ef3bf9c7fd313284530c1ad3813c3756ad7a86bb762e26bc46e8",
      },
    },
  };
}

async function withMockedImageProvenance({ sourceRevision }, fn) {
  const configText = JSON.stringify({
    config: {
      Labels: {
        "org.opencontainers.image.revision": sourceRevision,
      },
    },
  });
  const configDigest = sha256Digest(configText);
  const manifestText = JSON.stringify({
    schemaVersion: 2,
    config: { digest: configDigest },
  });
  const originalFetch = globalThis.fetch;
  process.env.TEE_LOCAL_IMAGE_DIGEST = sha256Digest(manifestText);
  process.env.TEE_LOCAL_IMAGE_REFERENCE = `registry.example/repo/image:${sourceRevision.slice(0, 12)}`;
  try {
    globalThis.fetch = async (url) => {
      if (String(url).includes("/manifests/")) {
        return new Response(manifestText, { status: 200 });
      }
      if (String(url).includes("/blobs/")) {
        return new Response(configText, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };
    return await fn();
  } finally {
    globalThis.fetch = originalFetch;
    delete process.env.TEE_LOCAL_IMAGE_DIGEST;
    delete process.env.TEE_LOCAL_IMAGE_REFERENCE;
  }
}

async function approveSuccessorArbitration({ decisionPacketDigest }) {
  return {
    rawDecision: canonicalStringify(approveDecision()),
    aiDecision: approveDecision(),
    arbitrationDigest: digestOf(`successor-arbitration:${decisionPacketDigest}`),
  };
}

function signPreapprovalLikeProposal(keys) {
  return {
    payload: {
      proposalId: "proposal-1",
    },
    payloadDigest: digestOf("proposal"),
    signingKeyId: keys.governanceKeyId,
  };
}
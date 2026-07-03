import { canonicalStringify, publicKeyFingerprint, sha256Digest } from "./canonical-json.js";
import { getAttestedImageDigest, getAttestedImageReference, getLauncherAttestationClaims, getProjectId, getWifAccessToken } from "./gcp-auth.js";
import { requestAttestationToken } from "./attestation.js";
import { getRouteRegistryStatus } from "./route-registry.js";
import { createInMemoryGovernanceKeyMaterial, buildActivationNonce, verifyGovernanceEnvelope } from "./governance-crypto.js";
import {
  createKmsBackedGovernanceKeyMaterial,
  isKmsGovernanceKeyConfigured,
} from "./kms-governance-key.js";
import {
  buildLatestPointer,
  isCapsulePersistenceConfigured,
  listCapsuleObjects,
  readLatestPointer,
  readStateCapsule,
  writeLatestPointer,
  writeStateCapsule,
} from "./capsule-store.js";
import {
  buildStateCapsuleAad,
  createEncryptedStateCapsule,
  decryptStateCapsule,
} from "./state-capsule.js";
import {
  ACTIVATION_PROOF_SCHEMA,
  assertPreapprovalMatchesCandidate,
  assertTenantAdmissionPayload,
  PREAPPROVAL_SCHEMA,
  signActivationProofCertificate,
  signGenesisCertificate,
  signPreapprovalCertificate,
  signRetirementCertificate,
  signSelfHealingProposalCertificate,
  signSuccessorCertificate,
  signTenantAdmissionCertificate,
  SUCCESSOR_SCHEMA,
  verifyLineage,
} from "./governance-certificates.js";
import { GOVERNANCE_SECURITY_BOUNDARY, SECRET_GOVERNANCE_CLASSIFICATION } from "./governance-boundary.js";
import { verifyConfidentialSpaceAttestation } from "./confidential-space-attestation.js";
import {
  buildHealthSnapshot,
  recordActivation,
  recordActivationChallenge,
  recordPreapproval,
  recordRetirement,
  recordRouteGateDenied,
} from "./governance-monitor.js";
import {
  buildSuccessorAcceptancePrompt,
  FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
  parseFirstPrinciplesDecision,
} from "./first-principles-review.js";
import { generateFirstPrinciplesContent } from "./vertex-gemini.js";
import {
  buildSuccessorDecisionPacket,
  evaluateSuccessorHardVetoes,
} from "./governance-successor-decision.js";
import { REPAIR_WORKER_RUNTIME_CONTRACT } from "./governance-repair-contract.js";
import { getRepairJobManifest } from "./governance-repair-jobs.js";
import { ensureModelPolicySupervisorState } from "./governance-model-policy-supervisor.js";

const ACTIVE = "active";
const INACTIVE = "inactive";
const ACTIVATING_SUCCESSOR = "activating_successor";
const RETIRED = "retired";
const TRUSTED_GENESIS_REVIEWER_IMAGE_DIGESTS = new Set([
  "sha256:a3b34e462346ef3bf9c7fd313284530c1ad3813c3756ad7a86bb762e26bc46e8",
]);

let state = null;
let capsuleSerial = 0;
let capsuleRestoreAttempted = false;
// Anti-rollback: capsuleSerial is a monotonic counter bound into each capsule's
// KMS-witness-signed AAD. On cold start we restore the highest AUTHENTIC serial
// in the bucket (not the mutable latest-pointer). `capsuleSerialBaselineEstablished`
// ensures the FIRST persist of a fresh genesis / operator re-genesis seeds the
// counter ABOVE any abandoned lineage's serials so it strictly supersedes them.
let capsuleSerialBaselineEstablished = false;
// Wall-clock of the last successful capsule persist, so the periodic heartbeat
// re-seals a fresh (higher-serial) capsule during quiet periods and the true
// head never ages out of the bucket's retention window.
let lastCapsulePersistAt = null;
// Cap on capsules verified during a cold-start scan. Honest operation keeps far
// fewer than this within the retention window; a larger count only arises from
// a hostile bucket owner flooding decoys (an availability non-goal).
const MAX_CAPSULES_SCANNED = 4096;
// Set when KMS-backed governance key initialization failed at boot. We fail
// closed (stay inactive; never activate or restore with an in-memory key) and
// let retryGovernanceRestoreIfDegraded() re-attempt KMS init + capsule restore
// on the refresh loop, so a transient KMS outage self-heals without operator
// intervention or a re-genesis.
let kmsUnavailable = false;

export function initializeGovernance({ mode = "inactive", keyMaterial: providedKeyMaterial = null, now = new Date() } = {}) {
  if (state) return state;
  if (mode === "active") {
    throw new Error("active governance can only be reached through genesis bootstrap or successor activation");
  }
  const keyMaterial = providedKeyMaterial || createInMemoryGovernanceKeyMaterial();
  const imageDigest = readCurrentImageDigest();
  const attestationDigest = digestLauncherAttestation();
  const lineage = [];
  let status = INACTIVE;

  if (mode === "genesis") {
    // Genesis-on-init exists for tests only. In production the genesis path
    // goes through bootstrapGenesisFromAttestedApproval which signs
    // asynchronously. The synchronous in-memory key material returns a
    // ready envelope here without ever entering the Promise branch of
    // signGovernancePayload, so this remains sync for the test path.
    const genesisCertificate = signGenesisCertificate({
      keyMaterial,
      imageDigest,
      routeRegistryStatus: getRouteRegistryStatus(),
      attestationDigest,
      now,
    });
    if (genesisCertificate && typeof genesisCertificate.then === "function") {
      throw new Error("initializeGovernance({ mode: 'genesis' }) requires synchronous key material; use initializeGovernanceAsync");
    }
    lineage.push(genesisCertificate);
    status = ACTIVE;
  }

  state = {
    status,
    epoch: status === ACTIVE ? 1 : 0,
    imageDigest,
    keyMaterial,
    lineage,
    latestPreapproval: null,
    latestSuccessorCertificate: null,
    latestRetirementCertificate: null,
    pendingSuccessorActivation: null,
    selfHealingProposals: [],
    modelPolicySupervisor: {
      schema: "femled.tee.model_policy.supervisor_state.v1",
      lastScanAt: null,
      lastEvaluationAt: null,
      lastScanStartedAt: null,
      lastProbeDigest: null,
      lastCandidateModel: null,
      lastProposalDigest: null,
      lastScanError: null,
    },
    pendingActivationChallenges: new Map(),
    transferredState: {
      schema: "femled.tee.governance.transferred_state.v1",
      routePolicy: emptyRoutePolicyState(),
    },
  };
  return state;
}

// Async initialization for production cold start.
//
// If GOVERNANCE_KMS_SIGNER_KEY_VERSION is set, the running TEE binds its
// governance signing identity to a Cloud KMS keyVersion gated by the WIF
// principal that is itself gated by the running container image digest.
// That makes the signing key portable across restarts of the same image,
// which is the precondition for restoring a sealed governance state
// capsule on cold start without inventing operator-driven recovery.
//
// Restore path (only when CAPSULE_BUCKET + GOVERNANCE_KMS_SIGNER_KEY_VERSION
// are both configured AND the latest capsule's AAD matches the running
// image + KMS key + state shape): restore lineage / epoch / transferredState
// / latestPreapproval / latestSuccessorCertificate / latestRetirementCertificate
// from the capsule and return `state.status === ACTIVE` directly. The
// running TEE skips genesis-bootstrap and tenant re-admission entirely.
//
// Anything that fails the integrity gates falls through to the standard
// `inactive` init. Recovery from that point is the standard
// genesis-bootstrap path against a trusted-reviewer TEE; there is no
// env-gated escape hatch.
export async function initializeGovernanceAsync({ mode = "inactive", keyMaterial: providedKeyMaterial = null, now = new Date(), createKeyMaterial = createKmsBackedGovernanceKeyMaterial } = {}) {
  if (state) return state;
  let keyMaterial = providedKeyMaterial;
  if (!keyMaterial && isKmsGovernanceKeyConfigured()) {
    try {
      keyMaterial = await createKeyMaterial();
      kmsUnavailable = false;
    } catch (error) {
      // FAIL CLOSED: do NOT silently fall back to an in-memory governance key.
      // An in-memory key is not recoverable across restarts and is not the
      // attested KMS-bound key, so activating or restoring with it yields a
      // lineage that can never self-restore (the root cause of the inactive
      // broker incident). Instead keep an inactive in-memory shell so /health,
      // /attestation, and the governance manifest still serve, mark KMS
      // unavailable, and skip restore. retryGovernanceRestoreIfDegraded()
      // re-attempts KMS init + capsule restore until Cloud KMS recovers.
      console.error("[governance] CRITICAL: KMS-backed governance key init failed; staying INACTIVE (no in-memory activation or restore) and will retry:", error.message);
      kmsUnavailable = true;
      keyMaterial = null;
    }
  }
  // If genesis was requested AND we picked a KMS-backed key material
  // (whose sign is async), use the async-aware init path: synthesize
  // the genesis cert through the same signGenesisCertificate flow but
  // await the Promise it returns.
  if (mode === "genesis" && keyMaterial?.kind === "kms-backed") {
    initializeGovernance({ mode: "inactive", keyMaterial, now });
    const current = getGovernanceState();
    const genesisCertificate = await signGenesisCertificate({
      keyMaterial,
      imageDigest: current.imageDigest,
      routeRegistryStatus: getRouteRegistryStatus(),
      attestationDigest: digestLauncherAttestation(),
      now,
    });
    current.status = ACTIVE;
    current.epoch = 1;
    current.lineage = [genesisCertificate];
    await persistGovernanceCapsuleBestEffort({ now });
    return state;
  }
  initializeGovernance({ mode, keyMaterial, now });
  if (state.status === INACTIVE && mode === "inactive" && isCapsulePersistenceConfigured() && state.keyMaterial.kind === "kms-backed") {
    try {
      await tryRestoreGovernanceFromCapsule({ now });
    } catch (error) {
      console.error("[governance] capsule restore attempt failed; remaining inactive:", error.message);
    }
  }
  return state;
}

export function resetGovernanceForTests(nextState = null) {
  state = nextState;
  capsuleSerial = 0;
  capsuleRestoreAttempted = false;
  capsuleSerialBaselineEstablished = false;
  lastCapsulePersistAt = null;
  kmsUnavailable = false;
}

// The highest authentic capsule serial restored/persisted this process. Surfaced
// on /health so an external probe can alert on an unexpected regression (a
// rollback attempt refused, or a stuck heartbeat).
export function getCapsuleSerial() {
  return capsuleSerial;
}

export function getGovernanceState() {
  return state || initializeGovernance();
}

export function isGovernanceActive() {
  return getGovernanceState().status === ACTIVE;
}

export function isGovernanceInactive() {
  return getGovernanceState().status === INACTIVE;
}

export function isGovernanceRetired() {
  return getGovernanceState().status === RETIRED;
}

export function assertActiveGovernance() {
  const current = getGovernanceState();
  if (current.status !== ACTIVE) {
    throw new Error(`TEE governance is ${current.status}; privileged operation requires active governance`);
  }
}

export function mayServePath(pathname) {
  const current = getGovernanceState();
  if (current.status === ACTIVE || current.status === ACTIVATING_SUCCESSOR) return true;
  if (pathname === "/health" || pathname === "/attestation" || pathname === "/.well-known/femled-tee-governance.json") return true;
  if (pathname === "/governance/genesis-bootstrap") return true;
  if (pathname.startsWith("/governance/activation-")) return true;
  if (current.status === INACTIVE && pathname === "/.well-known/femled-tee-policy.json") return true;
  // Operator-authorized self-attested genesis: a fresh INACTIVE candidate must
  // serve its own first-principles adjudication so operator-genesis.yml can obtain
  // the signed APPROVE that /governance/genesis-bootstrap consumes. Auth is still
  // enforced in the handler (genesis-scoped GitHub OIDC); the adjudication mutates
  // no state and releases no secrets.
  if (current.status === INACTIVE && pathname === "/first-principles/adjudicate") return true;
  recordRouteGateDenied({ pathname });
  return false;
}

export async function issuePreapprovalCertificate({
  candidate,
  hardCheckResults,
  aiDecision,
  aiResponseDigest,
  nonce,
  challengeDigest = null,
  requestDigest = null,
  authorizedCallerDigest = null,
  authorizedWorkflowRef = null,
  authorizedRunId = null,
  now = new Date(),
}) {
  assertActiveGovernance();
  const current = getGovernanceState();
  assertCandidateSelfHealingProposalIsLive(candidate);
  const envelope = await signPreapprovalCertificate({
    keyMaterial: current.keyMaterial,
    predecessorEpoch: current.epoch,
    candidate,
    hardCheckResults,
    aiDecision,
    aiResponseDigest,
    nonce,
    challengeDigest,
    requestDigest,
    authorizedCallerDigest,
    authorizedWorkflowRef,
    authorizedRunId,
    now,
  });
  current.latestPreapproval = envelope;
  recordPreapproval({ status: "issued", candidateDigest: candidate.candidateImageDigest });
  await persistGovernanceCapsuleBestEffort();
  return envelope;
}

// In production the active governance key MUST be the KMS-backed, attested,
// restorable key. Refuse genesis / successor activation with an in-memory key:
// an in-memory key is lost on restart and yields a lineage that can never
// self-restore from the capsule (the root cause of the avoidable re-genesis).
// Dev/test (NODE_ENV != production) may still use in-memory key material.
function assertKmsBackedGovernanceKeyInProduction(current) {
  if (process.env.NODE_ENV === "production" && current.keyMaterial.kind !== "kms-backed") {
    throw new Error("refusing to establish active governance with non-KMS-backed key material in production");
  }
}

export async function bootstrapGenesisFromAttestedApproval({
  request,
  response,
  targetImageDigest = null,
  now = new Date(),
  verifyAttestation = verifyConfidentialSpaceAttestation,
} = {}) {
  const current = getGovernanceState();
  if (current.status !== INACTIVE || current.lineage.length > 0) {
    throw new Error("genesis bootstrap requires inactive governance with empty lineage");
  }
  assertKmsBackedGovernanceKeyInProduction(current);
  const expectedTarget = targetImageDigest || current.imageDigest;
  if (expectedTarget !== current.imageDigest) {
    throw new Error("genesis bootstrap target image digest must match the running TEE image");
  }
  if (!request || typeof request !== "object" || !/^[a-f0-9]{40}$/i.test(request.headSha || "")) {
    throw new Error("genesis bootstrap requires the original adjudication request with a headSha");
  }
  if (!response?.payload || typeof response.attestationToken !== "string") {
    throw new Error("genesis bootstrap requires a signed TEE adjudication response");
  }

  const payloadDigest = sha256Digest(canonicalStringify(response.payload));
  if (response.payloadDigest !== payloadDigest) {
    throw new Error("genesis bootstrap adjudication payloadDigest mismatch");
  }
  const reviewerAttestation = await verifyAttestation(response.attestationToken, {
    expectedNonce: payloadDigest,
  });
  const reviewerImageDigest = reviewerAttestation.submods?.container?.image_digest || null;
  // Genesis bootstrap accepts a reviewer in one of two ways:
  //
  //   1. A pre-trusted seed reviewer whose attested image digest is hardcoded
  //      in TRUSTED_GENESIS_REVIEWER_IMAGE_DIGESTS (a previously-blessed image
  //      reviews the candidate -- continuity-preserving seed review).
  //   2. Operator-authorized self-attested re-genesis: the candidate attests
  //      its OWN running image digest. This is the explicit broken-continuity
  //      lineage-reset path (governance rulebook "Operator-authorized
  //      re-genesis"), used when no live trusted reviewer is available -- e.g.
  //      the active TEE is unrecoverably inactive and cannot adjudicate.
  //
  // The self-attested path is deliberately narrow: genesis bootstrap is only
  // reachable on a fresh INACTIVE TEE with an empty lineage (enforced above),
  // and the running image's source revision must equal the TEE-approved commit
  // (enforced below), so the self-review is still bound to a specific
  // GitHub-reviewed image -- not arbitrary code. Continuity IS broken: the new
  // lineage starts at this genesis and is NOT trusted by tenants until they
  // re-admit it. Tenant lineage-pinning plus freshly issued admission envelopes
  // are the trust boundary for a self-attested re-genesis, not an external
  // reviewer. An arbitrary third-party reviewer image (neither self nor a
  // trusted seed) is still rejected.
  const isSelfAttestedGenesis = reviewerImageDigest !== null && reviewerImageDigest === current.imageDigest;
  if (!isSelfAttestedGenesis && !TRUSTED_GENESIS_REVIEWER_IMAGE_DIGESTS.has(reviewerImageDigest)) {
    throw new Error(`genesis bootstrap reviewer image ${reviewerImageDigest || "unknown"} is not trusted for genesis`);
  }

  const payload = response.payload;
  if (payload.schema !== "femled.first_principles.adjudication.v1") {
    throw new Error("genesis bootstrap response has unexpected adjudication schema");
  }
  if (payload.repository !== "FemLed/auth-broker-tee") {
    throw new Error("genesis bootstrap adjudication repository mismatch");
  }
  if (payload.headSha !== request.headSha) {
    throw new Error("genesis bootstrap head SHA mismatch");
  }
  // The strong gate: the running image's source revision MUST equal the
  // TEE-approved commit. The reviewed diff is TEE-fetched from GitHub (its
  // diffDigest/changedFilesDigest/sourceEvidenceDigest live inside the attested
  // payload, already bound via the attestation eat_nonce == payloadDigest check),
  // so this binding -- not a regex on caller-supplied diff text -- proves the
  // running image is the genuinely reviewed self-governance genesis.
  const imageProvenance = await readCurrentImageProvenance();
  if (imageProvenance.sourceRevision !== payload.headSha) {
    throw new Error("genesis bootstrap running image revision is not bound to the TEE-approved commit");
  }
  if (payload.decision !== "APPROVE") {
    throw new Error("genesis bootstrap requires TEE APPROVE");
  }
  if (payload.expiresAt && Date.parse(payload.expiresAt) <= now.getTime()) {
    throw new Error("genesis bootstrap adjudication is expired");
  }
  if (request.nonce && payload.nonce !== request.nonce) {
    throw new Error("genesis bootstrap nonce mismatch between request and adjudication");
  }

  const genesisBootstrap = {
    schema: "femled.tee.governance.genesis_bootstrap.v1",
    reviewerImageDigest,
    adjudicationPayloadDigest: payloadDigest,
    adjudicationHeadSha: payload.headSha,
    adjudicationWorkflowRunId: payload.workflowRunId,
    targetImageDigest: current.imageDigest,
    targetImageReference: imageProvenance.imageReference,
    targetImageSourceRevision: imageProvenance.sourceRevision,
    targetImageConfigDigest: imageProvenance.configDigest,
    requestDigest: sha256Digest(canonicalStringify({
      repository: request.repository,
      eventName: request.eventName,
      headSha: request.headSha,
      changedFilesDigest: payload.changedFilesDigest,
      diffDigest: payload.diffDigest,
      sourceEvidenceDigest: payload.sourceEvidenceDigest || null,
      workflowRunId: request.workflowRunId,
    })),
    bootstrappedAt: now.toISOString(),
  };
  const genesisCertificate = await signGenesisCertificate({
    keyMaterial: current.keyMaterial,
    imageDigest: current.imageDigest,
    routeRegistryStatus: getRouteRegistryStatus(),
    attestationDigest: digestLauncherAttestation(),
    genesisBootstrap,
    now,
  });

  current.status = ACTIVE;
  current.epoch = 1;
  current.lineage = [genesisCertificate];
  await persistGovernanceCapsuleBestEffort();

  return buildGovernanceManifestPayload();
}

export async function issueSelfHealingProposal({ proposal, healthSnapshot = null, internalEventDigests = [], industryTelemetryDigest = null, now = new Date() }) {
  assertActiveGovernance();
  const current = getGovernanceState();
  const snapshot = healthSnapshot || buildHealthSnapshot({
    governanceStatus: current.status,
    epoch: current.epoch,
    lineageDigest: sha256Digest(canonicalStringify(current.lineage)),
  });
  const envelope = await signSelfHealingProposalCertificate({
    keyMaterial: current.keyMaterial,
    epoch: current.epoch,
    proposal,
    healthSnapshotDigest: sha256Digest(canonicalStringify(snapshot)),
    internalEventDigests,
    industryTelemetryDigest,
    now,
  });
  current.selfHealingProposals.push(envelope);
  current.selfHealingProposals = current.selfHealingProposals.slice(-20);
  return envelope;
}

export async function issueTenantAdmissionCertificate({
  tenant,
  tenantRouteSigningKeys,
  minRouteVersion,
  allowedApiHosts,
  allowedAppHosts,
  allowedBrokerAudiences,
  registrationProofDigest = null,
  now = new Date(),
  ttlMs,
}) {
  assertActiveGovernance();
  const current = getGovernanceState();
  assertTenantAdmissionDoesNotReplaceExistingKey(current, { tenant, tenantRouteSigningKeys });
  const lineageDigest = sha256Digest(canonicalStringify(current.lineage));
  const envelope = await signTenantAdmissionCertificate({
    keyMaterial: current.keyMaterial,
    epoch: current.epoch,
    lineageDigest,
    tenant,
    tenantRouteSigningKeys,
    minRouteVersion,
    allowedApiHosts,
    allowedAppHosts,
    allowedBrokerAudiences,
    registrationProofDigest,
    now,
    ...(ttlMs ? { ttlMs } : {}),
  });
  recordTenantAdmissionInState(envelope.payload, envelope.payloadDigest);
  await persistGovernanceCapsuleBestEffort();
  return envelope;
}

export function verifyTenantAdmissionEnvelope(envelope, { now = new Date() } = {}) {
  const current = getGovernanceState();
  const publicKeyPem = resolveGovernancePublicKeyForKeyId(envelope?.signingKeyId, current);
  const payload = verifyGovernanceEnvelope(envelope, publicKeyPem, { now });
  assertTenantAdmissionPayload(payload, { now });
  if (payload.governanceKeyId !== envelope.signingKeyId) {
    throw new Error("tenant admission governanceKeyId must match envelope signingKeyId");
  }
  const policy = ensureRoutePolicyState(current);
  const admitted = policy.admittedTenants[payload.tenant];
  if (admitted) {
    if (payload.minRouteVersion < admitted.minRouteVersion) {
      throw new Error("tenant admission minRouteVersion is below TEE route policy state");
    }
    const currentKeyIds = new Set((payload.tenantRouteSigningKeys || []).map((key) => key.keyId));
    for (const revoked of admitted.revokedRouteKeyIds || []) {
      if (currentKeyIds.has(revoked)) {
        throw new Error(`tenant admission includes revoked route key ${revoked}`);
      }
    }
  }
  return payload;
}

export function recordAcceptedRouteVersion({ tenant, routeVersion, routeDigest }) {
  const current = getGovernanceState();
  const policy = ensureRoutePolicyState(current);
  const admitted = policy.admittedTenants[tenant];
  if (!admitted) return;
  if (Number.isInteger(routeVersion) && routeVersion > (admitted.latestAcceptedRouteVersion || 0)) {
    admitted.latestAcceptedRouteVersion = routeVersion;
    admitted.latestAcceptedRouteDigest = routeDigest || null;
  }
}

export function getRoutePolicyStateDigest() {
  return sha256Digest(canonicalStringify(ensureRoutePolicyState(getGovernanceState())));
}

export function createActivationChallenge({ preapprovalEnvelope, candidateGovernancePublicKeyPem, candidateActivationPublicKeyPem, candidateImageDigest, random = cryptoRandomBase64Url() }) {
  assertActiveGovernance();
  const current = getGovernanceState();
  const preapproval = verifyGovernanceEnvelope(preapprovalEnvelope, current.keyMaterial.governancePublicKeyPem);
  if (preapproval.schema !== PREAPPROVAL_SCHEMA) throw new Error("activation requires preapproval certificate");
  const activationNonce = buildActivationNonce({
    candidateImageDigest,
    candidateGovernancePublicKeyPem,
    candidateActivationPublicKeyPem,
    preapprovalPayloadDigest: preapprovalEnvelope.payloadDigest,
    random,
  });
  current.pendingActivationChallenges.set(activationNonce, {
    activationNonce,
    preapprovalEnvelope,
    candidateGovernancePublicKeyPem,
    candidateActivationPublicKeyPem,
    candidateImageDigest,
    createdAt: new Date().toISOString(),
  });
  recordActivationChallenge({ candidateDigest: candidateImageDigest });
  return { activationNonce };
}

export async function completeActivation({
  preapprovalEnvelope,
  candidate,
  candidateAttestationToken,
  candidateGovernancePublicKeyPem,
  candidateGovernanceKeyId,
  candidateActivationPublicKeyPem,
  activationNonce,
  now = new Date(),
  verifyAttestation = verifyConfidentialSpaceAttestation,
  arbitrateSuccessor = arbitrateSuccessorWithGemini,
}) {
  assertActiveGovernance();
  const current = getGovernanceState();
  assertKmsBackedGovernanceKeyInProduction(current);
  let challenge;
  let preapproval;
  let attestation;
  let successorDecision;
  try {
    challenge = current.pendingActivationChallenges.get(activationNonce);
    if (!challenge) throw new Error("unknown governance activation nonce");
    if (challenge.preapprovalEnvelope.payloadDigest !== preapprovalEnvelope.payloadDigest) {
      throw new Error("activation preapproval digest mismatch");
    }
    if (challenge.candidateImageDigest !== candidate.candidateImageDigest) {
      throw new Error("activation candidate image digest mismatch");
    }
    if (challenge.candidateGovernancePublicKeyPem !== candidateGovernancePublicKeyPem) {
      throw new Error("activation candidate governance key mismatch");
    }
    if (challenge.candidateActivationPublicKeyPem !== candidateActivationPublicKeyPem) {
      throw new Error("activation candidate activation key mismatch");
    }
    const expectedCandidateKeyId = `sha256:${publicKeyFingerprint(candidateGovernancePublicKeyPem)}`;
    if (candidateGovernanceKeyId !== expectedCandidateKeyId) {
      throw new Error("activation candidate governance key id mismatch");
    }

    preapproval = verifyGovernanceEnvelope(preapprovalEnvelope, current.keyMaterial.governancePublicKeyPem, { now });
    assertPreapprovalMatchesCandidate(preapproval, candidate);
    attestation = await verifyAttestation(candidateAttestationToken, {
      expectedNonce: activationNonce,
      expectedImageDigest: candidate.candidateImageDigest,
    });
    const { packet, packetDigest } = buildSuccessorDecisionPacket({
      currentManifest: buildGovernanceManifestPayload(),
      candidate,
      preapprovalEnvelope,
      preapprovalPayload: preapproval,
      candidateAttestationToken,
      candidateAttestation: attestation,
      candidateGovernanceKeyId,
      candidateGovernancePublicKeyPem,
      candidateActivationPublicKeyPem,
      activationNonce,
      expectedCandidateImageDigest: candidate.candidateImageDigest,
      expectedActivationNonce: activationNonce,
      now,
    });
    const hardVetoResults = evaluateSuccessorHardVetoes(packet);
    if (hardVetoResults.status !== "passed") {
      throw new Error(`successor hard veto failed: ${hardVetoResults.failures.join("; ")}`);
    }
    successorDecision = normalizeSuccessorArbitrationResult(await arbitrateSuccessor({
      decisionPacket: packet,
      decisionPacketDigest: packetDigest,
      hardVetoResults,
    }));
    if (successorDecision.aiDecision.decision !== "APPROVE") {
      throw new Error(`successor arbitration requested changes: ${successorDecision.aiDecision.reasoning}`);
    }
    if ((successorDecision.aiDecision.violatedPrinciples || []).length > 0) {
      throw new Error("successor arbitration reported violated principles");
    }
    successorDecision = {
      ...successorDecision,
      decisionPacket: packet,
      decisionPacketDigest: packetDigest,
      hardVetoResults,
    };
  } catch (error) {
    recordActivation({ status: "failed", reason: error.message, candidateDigest: candidate?.candidateImageDigest });
    throw error;
  }

  const successorCertificate = await signSuccessorCertificate({
    keyMaterial: current.keyMaterial,
    predecessorEpoch: current.epoch,
    successorEpoch: current.epoch + 1,
    candidateImageDigest: candidate.candidateImageDigest,
    candidateAttestationDigest: sha256Digest(candidateAttestationToken),
    candidateAttestationNonce: activationNonce,
    preapprovalPayloadDigest: preapprovalEnvelope.payloadDigest,
    successorDecisionPacketDigest: successorDecision.decisionPacketDigest,
    successorArbitrationDigest: successorDecision.arbitrationDigest,
    successorGovernancePublicKeyPem: candidateGovernancePublicKeyPem,
    successorGovernanceKeyId: candidateGovernanceKeyId,
    successorActivationPublicKeyPem: candidateActivationPublicKeyPem,
    now,
  });

  const transferAad = {
    successorPayloadDigest: successorCertificate.payloadDigest,
    predecessorGovernanceKeyId: current.keyMaterial.governanceKeyId,
    successorGovernanceKeyId: candidateGovernanceKeyId,
    candidateImageDigest: candidate.candidateImageDigest,
    activationNonce,
  };
  const encryptedState = current.keyMaterial.encryptStateFor(candidateActivationPublicKeyPem, {
    schema: "femled.tee.governance.transferable_state.v1",
    lineage: [...current.lineage, successorCertificate],
    epoch: current.epoch + 1,
    transferredState: current.transferredState,
  }, transferAad);

  current.status = ACTIVATING_SUCCESSOR;
  current.pendingSuccessorActivation = {
    schema: "femled.tee.governance.pending_successor_activation.v1",
    activationNonce,
    candidateImageDigest: candidate.candidateImageDigest,
    candidateGovernanceKeyId,
    candidateGovernancePublicKeyPem,
    candidateActivationPublicKeyPem,
    successorCertificate,
    successorPayloadDigest: successorCertificate.payloadDigest,
    successorDecisionPacketDigest: successorDecision.decisionPacketDigest,
    successorArbitrationDigest: successorDecision.arbitrationDigest,
    issuedAt: now.toISOString(),
    expiresAt: successorCertificate.payload.expiresAt,
  };
  current.latestSuccessorCertificate = successorCertificate;
  await persistGovernanceCapsuleBestEffort();

  return {
    successorCertificate,
    encryptedState,
    candidateAttestation: {
      imageDigest: attestation.submods?.container?.image_digest || null,
      dbgstat: attestation.dbgstat,
      swname: attestation.swname,
    },
    successorDecision: {
      decisionPacketDigest: successorDecision.decisionPacketDigest,
      arbitrationDigest: successorDecision.arbitrationDigest,
      hardVetoStatus: successorDecision.hardVetoResults.status,
      decision: successorDecision.aiDecision.decision,
    },
    finalAcceptance: "pending_candidate_apply_and_predecessor_finalize",
  };
}

export async function applyActivationBundle({ successorCertificate, encryptedState, predecessorActivationPublicKeyPem, activationNonce, now = new Date() }) {
  const current = getGovernanceState();
  if (current.status !== INACTIVE) throw new Error("activation bundle can only be applied to inactive candidate");
  assertKmsBackedGovernanceKeyInProduction(current);
  if (successorCertificate?.payload?.schema !== SUCCESSOR_SCHEMA) {
    throw new Error("activation bundle successor certificate missing");
  }
  if (successorCertificate.payload.successorGovernanceKeyId !== current.keyMaterial.governanceKeyId) {
    throw new Error("activation bundle successor governance key mismatch");
  }
  if (successorCertificate.payload.successorGovernancePublicKeyPem !== current.keyMaterial.governancePublicKeyPem) {
    throw new Error("activation bundle successor governance public key mismatch");
  }
  if (successorCertificate.payload.successorActivationPublicKeyPem !== current.keyMaterial.activationPublicKeyPem) {
    throw new Error("activation bundle successor activation key mismatch");
  }
  if (successorCertificate.payload.candidateImageDigest !== current.imageDigest) {
    throw new Error("activation bundle candidate image digest mismatch");
  }
  if (successorCertificate.payload.candidateAttestationNonce !== activationNonce) {
    throw new Error("activation bundle nonce mismatch");
  }
  const transferAad = {
    successorPayloadDigest: successorCertificate.payloadDigest,
    predecessorGovernanceKeyId: successorCertificate.payload.predecessorGovernanceKeyId,
    successorGovernanceKeyId: current.keyMaterial.governanceKeyId,
    candidateImageDigest: successorCertificate.payload.candidateImageDigest,
    activationNonce,
  };
  const transferred = current.keyMaterial.decryptState({
    ...encryptedState,
    senderActivationPublicKeyPem: predecessorActivationPublicKeyPem || encryptedState.senderActivationPublicKeyPem,
  }, transferAad);
  const verified = verifyLineage(transferred.lineage, { now, enforceTerminalExpiry: true });
  if (verified.currentEpoch !== successorCertificate.payload.successorEpoch) {
    throw new Error("transferred lineage epoch mismatch");
  }
  if (verified.currentGovernancePublicKeyPem !== current.keyMaterial.governancePublicKeyPem) {
    throw new Error("transferred lineage current governance key mismatch");
  }
  const terminalCertificate = transferred.lineage[transferred.lineage.length - 1];
  if (terminalCertificate?.payloadDigest !== successorCertificate.payloadDigest) {
    throw new Error("transferred lineage does not end with supplied successor certificate");
  }
  current.status = ACTIVE;
  current.epoch = transferred.epoch;
  current.lineage = transferred.lineage;
  current.transferredState = normalizeTransferredState(transferred.transferredState);
  current.latestSuccessorCertificate = successorCertificate;
  const lineageDigest = sha256Digest(canonicalStringify(current.lineage));
  const activationProof = await signActivationProofCertificate({
    keyMaterial: current.keyMaterial,
    epoch: current.epoch,
    successorPayloadDigest: successorCertificate.payloadDigest,
    activationNonce,
    candidateImageDigest: current.imageDigest,
    lineageDigest,
    now,
  });
  await persistGovernanceCapsuleBestEffort();

  return {
    ...buildGovernanceManifestPayload(),
    activationProof,
  };
}

export async function finalizeActivation({ activationProof, now = new Date() } = {}) {
  const current = getGovernanceState();
  if (current.status !== ACTIVATING_SUCCESSOR) {
    throw new Error(`activation finalize requires activating_successor governance, got ${current.status}`);
  }
  const pending = current.pendingSuccessorActivation;
  if (!pending?.successorCertificate) {
    throw new Error("activation finalize requires pending successor activation");
  }
  const proof = verifyGovernanceEnvelope(activationProof, pending.candidateGovernancePublicKeyPem, { now });
  if (proof.schema !== ACTIVATION_PROOF_SCHEMA) {
    throw new Error("activation proof schema mismatch");
  }
  const expectedLineage = [...current.lineage, pending.successorCertificate];
  const expectedLineageDigest = sha256Digest(canonicalStringify(expectedLineage));
  for (const [key, value] of Object.entries({
    successorPayloadDigest: pending.successorPayloadDigest,
    activationNonce: pending.activationNonce,
    candidateImageDigest: pending.candidateImageDigest,
    lineageDigest: expectedLineageDigest,
    epoch: current.epoch + 1,
    governanceKeyId: pending.candidateGovernanceKeyId,
  })) {
    if (proof[key] !== value) {
      throw new Error(`activation proof ${key} mismatch`);
    }
  }
  verifyLineage(expectedLineage, { now, enforceTerminalExpiry: true });
  const retirementCertificate = await signRetirementCertificate({
    keyMaterial: current.keyMaterial,
    retiredEpoch: current.epoch,
    successorEpoch: current.epoch + 1,
    successorGovernanceKeyId: pending.candidateGovernanceKeyId,
    successorPayloadDigest: pending.successorPayloadDigest,
    now,
  });
  current.status = RETIRED;
  current.latestRetirementCertificate = retirementCertificate;
  current.pendingActivationChallenges.clear();
  current.pendingSuccessorActivation = null;
  recordActivation({ status: "success", candidateDigest: pending.candidateImageDigest });
  recordRetirement({ successorDigest: pending.successorPayloadDigest });
  await persistGovernanceCapsuleBestEffort();
  return {
    status: "retired",
    successorCertificate: pending.successorCertificate,
    retirementCertificate,
    activationProof,
  };
}

export function buildGovernanceManifestPayload() {
  const current = getGovernanceState();
  const routeRegistry = getRouteRegistryStatus();
  const lineageDigest = sha256Digest(canonicalStringify(current.lineage));
  const health = buildHealthSnapshot({
    governanceStatus: current.status,
    epoch: current.epoch,
    lineageDigest,
  });
  const openProposals = current.selfHealingProposals.filter((proposal) =>
    !proposal.payload.expiresAt || Date.parse(proposal.payload.expiresAt) > Date.now()
  );
  const repairJobs = getRepairJobManifest();
  return {
    schema: "femled.tee.governance.manifest.v1",
    status: current.status,
    epoch: current.epoch,
    governanceKeyId: current.keyMaterial.governanceKeyId,
    activationKeyId: current.keyMaterial.activationKeyId,
    governancePublicKeyPem: current.keyMaterial.governancePublicKeyPem,
    activationPublicKeyPem: current.keyMaterial.activationPublicKeyPem,
    imageDigest: current.imageDigest,
    lineage: current.lineage,
    lineageDigest,
    latestSuccessorCertificate: current.latestSuccessorCertificate,
    latestRetirementCertificate: current.latestRetirementCertificate,
    pendingSuccessorActivation: current.pendingSuccessorActivation,
    routeTrustAnchorsDigest: routeRegistry.trustAnchorsDigest,
    routeBundleDigest: routeRegistry.routeBundleDigest,
    routePolicyStateDigest: getRoutePolicyStateDigest(),
    modelPolicyDigest: FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
    health,
    selfHealing: {
      schema: "femled.tee.self_healing.manifest.v1",
      openProposalDigests: openProposals.map((proposal) => proposal.payloadDigest),
      openProposals,
      modelPolicySupervisor: ensureModelPolicySupervisorState(current),
      repairWorkerRuntimeContract: REPAIR_WORKER_RUNTIME_CONTRACT,
      repairJobs,
    },
    securityBoundary: GOVERNANCE_SECURITY_BOUNDARY,
    secretClassification: SECRET_GOVERNANCE_CLASSIFICATION,
    issuedAt: new Date().toISOString(),
  };
}

function recordTenantAdmissionInState(payload, payloadDigest) {
  const current = getGovernanceState();
  const policy = ensureRoutePolicyState(current);
  const existing = policy.admittedTenants[payload.tenant] || {};
  policy.admittedTenants[payload.tenant] = {
    tenant: payload.tenant,
    admissionPayloadDigest: payloadDigest,
    governanceKeyId: payload.governanceKeyId,
    governanceEpoch: payload.governanceEpoch,
    minRouteVersion: Math.max(existing.minRouteVersion || 1, payload.minRouteVersion),
    tenantRouteSigningKeys: payload.tenantRouteSigningKeys,
    allowedApiHosts: payload.allowedApiHosts,
    allowedAppHosts: payload.allowedAppHosts,
    allowedBrokerAudiences: payload.allowedBrokerAudiences,
    revokedRouteKeyIds: existing.revokedRouteKeyIds || [],
    latestAcceptedRouteVersion: existing.latestAcceptedRouteVersion || 0,
    latestAcceptedRouteDigest: existing.latestAcceptedRouteDigest || null,
    updatedAt: new Date().toISOString(),
  };
}

function assertTenantAdmissionDoesNotReplaceExistingKey(current, { tenant, tenantRouteSigningKeys }) {
  const existing = ensureRoutePolicyState(current).admittedTenants[tenant];
  if (!existing) return;
  const existingKeys = canonicalStringify((existing.tenantRouteSigningKeys || []).map(routeKeyFingerprint));
  const nextKeys = canonicalStringify((tenantRouteSigningKeys || []).map(routeKeyFingerprint));
  if (existingKeys !== nextKeys) {
    throw new Error("tenant route key replacement requires an explicit key-rotation certificate");
  }
}

function routeKeyFingerprint(key) {
  return {
    alg: key.alg,
    keyId: key.keyId,
    publicKeyPem: key.publicKeyPem,
  };
}

function resolveGovernancePublicKeyForKeyId(keyId, current) {
  if (!keyId || typeof keyId !== "string") {
    throw new Error("tenant admission envelope must include signingKeyId");
  }
  for (const envelope of current.lineage || []) {
    const payload = envelope.payload || {};
    if (payload.governanceKeyId === keyId && payload.governancePublicKeyPem) {
      return payload.governancePublicKeyPem;
    }
    if (payload.successorGovernanceKeyId === keyId && payload.successorGovernancePublicKeyPem) {
      return payload.successorGovernancePublicKeyPem;
    }
  }
  if (current.keyMaterial?.governanceKeyId === keyId) {
    return current.keyMaterial.governancePublicKeyPem;
  }
  throw new Error(`tenant admission signing key ${keyId} is not in accepted governance lineage`);
}

function normalizeTransferredState(value = {}) {
  return {
    schema: "femled.tee.governance.transferred_state.v1",
    ...value,
    routePolicy: normalizeRoutePolicyState(value.routePolicy),
  };
}

function ensureRoutePolicyState(current) {
  current.transferredState = normalizeTransferredState(current.transferredState);
  return current.transferredState.routePolicy;
}

function normalizeRoutePolicyState(value = {}) {
  return {
    schema: "femled.tee.route_policy_state.v1",
    admittedTenants: value.admittedTenants && typeof value.admittedTenants === "object"
      ? value.admittedTenants
      : {},
  };
}

function emptyRoutePolicyState() {
  return normalizeRoutePolicyState();
}

function assertCandidateSelfHealingProposalIsLive(candidate) {
  if (!candidate.selfHealingProposalDigest) return;
  const current = getGovernanceState();
  const match = current.selfHealingProposals.find((proposal) =>
    proposal.payloadDigest === candidate.selfHealingProposalDigest &&
    (!proposal.payload.expiresAt || Date.parse(proposal.payload.expiresAt) > Date.now())
  );
  if (!match) {
    recordPreapproval({ status: "rejected", reason: "self-healing proposal is not live", candidateDigest: candidate.candidateImageDigest });
    throw new Error("candidate references missing or expired self-healing proposal");
  }
}

export async function attestGovernanceManifest() {
  const payload = buildGovernanceManifestPayload();
  const payloadDigest = sha256Digest(canonicalStringify(payload));
  return {
    payload,
    payloadDigest,
    attestationToken: await requestAttestationToken([payloadDigest]),
    attestationBinding: "google-confidential-space-eat-nonce-sha256",
  };
}

function digestLauncherAttestation() {
  try {
    return sha256Digest(canonicalStringify(getLauncherAttestationClaims()));
  } catch {
    return null;
  }
}

function readCurrentImageDigest() {
  try {
    return getAttestedImageDigest();
  } catch (error) {
    if (process.env.NODE_ENV === "production" && !process.env.TEE_LOCAL_IMAGE_DIGEST) {
      throw error;
    }
    return process.env.TEE_LOCAL_IMAGE_DIGEST || "sha256:0000000000000000000000000000000000000000000000000000000000000000";
  }
}

function readCurrentImageReference() {
  try {
    return getAttestedImageReference();
  } catch {
    return process.env.TEE_LOCAL_IMAGE_REFERENCE || null;
  }
}

async function readCurrentImageProvenance() {
  const imageReference = readCurrentImageReference();
  const imageDigest = readCurrentImageDigest();
  if (!imageReference || !imageDigest) {
    throw new Error("running image reference and digest are required for genesis bootstrap");
  }
  const { registry, repository } = parseImageReference(imageReference);
  const accessToken = isExpectedArtifactRegistryImage(registry, repository) ? await getWifAccessToken() : null;
  const manifestResp = await fetch(`https://${registry}/v2/${repository}/manifests/${imageDigest}`, {
    headers: {
      Accept: [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
      ].join(", "),
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    },
    signal: AbortSignal.timeout(15000),
  });
  if (!manifestResp.ok) {
    throw new Error(`genesis bootstrap failed to fetch running image manifest: ${manifestResp.status}`);
  }
  const manifestText = await manifestResp.text();
  const manifestDigest = sha256Digest(manifestText);
  if (manifestDigest !== imageDigest) {
    throw new Error(`running image manifest digest mismatch: expected ${imageDigest}, got ${manifestDigest}`);
  }
  const manifest = JSON.parse(manifestText);
  const configDigest = manifest.config?.digest;
  if (!configDigest) {
    throw new Error("running image manifest is missing config digest");
  }
  const configResp = await fetch(`https://${registry}/v2/${repository}/blobs/${configDigest}`, {
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
    signal: AbortSignal.timeout(15000),
  });
  if (!configResp.ok) {
    throw new Error(`genesis bootstrap failed to fetch running image config: ${configResp.status}`);
  }
  const configBytes = Buffer.from(await configResp.arrayBuffer());
  const fetchedConfigDigest = sha256Digest(configBytes);
  if (fetchedConfigDigest !== configDigest) {
    throw new Error(`running image config digest mismatch: expected ${configDigest}, got ${fetchedConfigDigest}`);
  }
  const config = JSON.parse(configBytes.toString("utf8"));
  const sourceRevision = config.config?.Labels?.["org.opencontainers.image.revision"] || null;
  if (!/^[a-f0-9]{40}$/i.test(sourceRevision || "")) {
    throw new Error("running image config is missing org.opencontainers.image.revision");
  }
  return {
    imageReference,
    imageDigest,
    sourceRevision,
    configDigest,
  };
}

function parseImageReference(imageReference) {
  const withoutDigest = imageReference.includes("@")
    ? imageReference.slice(0, imageReference.indexOf("@"))
    : imageReference;
  const slash = withoutDigest.indexOf("/");
  if (slash <= 0) {
    throw new Error("running image reference must include registry/repository");
  }
  return {
    registry: withoutDigest.slice(0, slash),
    repository: withoutDigest.slice(slash + 1).replace(/:[^/:]+$/, ""),
  };
}

function isExpectedArtifactRegistryImage(registry, repository) {
  return registry === "us-west1-docker.pkg.dev" &&
    repository === "prod-femled-couple-router/auth-broker/auth-broker-tee";
}

function cryptoRandomBase64Url() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`;
}

async function arbitrateSuccessorWithGemini({ decisionPacket, hardVetoResults }) {
  const prompt = buildSuccessorAcceptancePrompt({ decisionPacket, hardVetoResults });
  const rawDecision = await generateFirstPrinciplesContent(prompt);
  return {
    rawDecision,
    aiDecision: parseFirstPrinciplesDecision(rawDecision),
    arbitrationDigest: sha256Digest(rawDecision),
  };
}

function normalizeSuccessorArbitrationResult(result) {
  if (!result?.aiDecision) {
    throw new Error("successor arbitration result missing aiDecision");
  }
  const rawDecision = result.rawDecision || canonicalStringify(result.aiDecision);
  return {
    rawDecision,
    aiDecision: result.aiDecision,
    arbitrationDigest: result.arbitrationDigest || sha256Digest(rawDecision),
  };
}

// ---------------------------------------------------------------------------
// Governance state capsule persistence (KMS-sealed, GCS-backed)
//
// Every mutation that issues a lineage cert or updates routePolicy ends with
// `await persistGovernanceCapsuleBestEffort()`. The capsule write is best-
// effort because the call path is on a request-handling hot path; a transient
// GCS error must not roll back a signed certificate that is already in
// `current.lineage`. The next mutation re-attempts, and on cold start any
// inconsistency surfaces as "capsule does not match running image" and we
// fall back to inactive rather than restoring a stale state.
//
// The persistable subset deliberately excludes:
//   - `keyMaterial` (governance signing key lives in KMS by reference; the
//     X25519 activation key is per-handoff and regenerated on cold start)
//   - `pendingActivationChallenges` (transient HTTP nonces with 30s TTL)
//   - `selfHealingProposals` (rebuildable from monitor evidence)
//   - `modelPolicySupervisor` (rebuildable from supervisor scans)
//   - `pendingSuccessorActivation` (only meaningful inside the predecessor
//     between activation-complete and activation-finalize; if the VM
//     restarts mid-handoff, the candidate has already received its capsule
//     out-of-band and the predecessor stays retired-via-cert-only)
// ---------------------------------------------------------------------------

const PERSISTABLE_STATE_SCHEMA = "femled.auth_broker_tee.governance.persistable_state.v1";

export function buildPersistableState(current = getGovernanceState()) {
  return {
    schema: PERSISTABLE_STATE_SCHEMA,
    status: current.status,
    epoch: current.epoch,
    imageDigest: current.imageDigest,
    governanceKeyId: current.keyMaterial.governanceKeyId,
    governancePublicKeyPem: current.keyMaterial.governancePublicKeyPem,
    governanceKmsKeyVersion: current.keyMaterial.kmsKeyVersion || null,
    lineage: current.lineage,
    latestPreapproval: current.latestPreapproval,
    latestSuccessorCertificate: current.latestSuccessorCertificate,
    latestRetirementCertificate: current.latestRetirementCertificate,
    transferredState: current.transferredState,
  };
}

export function isGovernancePersistenceEnabled() {
  if (!isCapsulePersistenceConfigured()) return false;
  const current = state || null;
  if (!current) return false;
  return current.keyMaterial.kind === "kms-backed";
}

export async function persistGovernanceCapsuleBestEffort({ now = new Date() } = {}) {
  if (!isGovernancePersistenceEnabled()) return null;
  try {
    return await persistGovernanceCapsule({ now });
  } catch (error) {
    console.error("[governance] capsule persist failed (best-effort):", error.message);
    return null;
  }
}

export async function persistGovernanceCapsule({ now = new Date() } = {}) {
  const current = getGovernanceState();
  if (current.keyMaterial.kind !== "kms-backed") {
    throw new Error("capsule persistence requires KMS-backed governance key material");
  }
  if (!isCapsulePersistenceConfigured()) {
    throw new Error("CAPSULE_BUCKET and GOVERNANCE_KMS_SIGNER_KEY_VERSION must both be configured");
  }
  if (!capsuleSerialBaselineEstablished) {
    // First persist of this process without a prior restore (a fresh genesis or
    // an operator re-genesis on the same image + KMS key). Seed the serial ABOVE
    // the highest authentic serial already in the bucket so this lineage
    // strictly supersedes any abandoned one -- otherwise "highest serial wins"
    // on the next cold boot could resurrect the abandoned lineage's
    // higher-serial capsules (they share this KMS key, so they pass the
    // active-key gate too).
    const bucketMax = await maxVerifiedCapsuleSerial({ now, current });
    if (bucketMax > capsuleSerial) capsuleSerial = bucketMax;
    capsuleSerialBaselineEstablished = true;
  }
  capsuleSerial += 1;
  const persistableState = buildPersistableState(current);
  const transferredStateDigest = sha256Digest(canonicalStringify(current.transferredState));
  const lineageDigest = sha256Digest(canonicalStringify(current.lineage));
  const governancePublicKeyDigest = `sha256:${publicKeyFingerprint(current.keyMaterial.governancePublicKeyPem)}`;
  const aad = buildStateCapsuleAad({
    imageDigest: current.imageDigest,
    imageReference: readCurrentImageReference() || `image-digest:${current.imageDigest}`,
    governanceKmsKeyVersion: current.keyMaterial.kmsKeyVersion,
    governancePublicKeyDigest,
    lineageDigest,
    epoch: current.epoch,
    transferredStateDigest,
    status: current.status,
    gcpProjectId: getProjectId(),
    capsuleSerial,
  });
  const kmsPublicKeyPem = await current.keyMaterial.getKmsPublicKeyPem();
  const capsule = await createEncryptedStateCapsule({
    persistableState,
    aad,
    kmsSign: (buffer) => current.keyMaterial.signWithKms(buffer),
    kmsPublicKeyPem,
    now,
  });
  await writeStateCapsule(capsule);
  await writeLatestPointer(buildLatestPointer({
    capsuleDigest: capsule.capsuleDigest,
    imageDigest: current.imageDigest,
    governanceKmsKeyVersion: current.keyMaterial.kmsKeyVersion,
    epoch: current.epoch,
    status: current.status,
    capsuleSerial,
    lineageDigest,
    now,
  }));
  lastCapsulePersistAt = now;
  return { capsuleDigest: capsule.capsuleDigest, capsuleSerial };
}

// Anti-rollback restore. Rather than trusting the mutable latest-pointer (which
// a bucket-write attacker can rewind to an older capsule), we ENUMERATE every
// capsule the bucket holds, keep only those that are AUTHENTIC (KMS-witness
// signed) and bind to this running image + KMS key + governance public key with
// a valid predecessor-signed lineage whose ACTIVE key is our KMS key, and
// restore the one with the highest authentic capsuleSerial. The serial lives in
// the witness-signed AAD so it cannot be forged upward; the bucket's locked
// retention policy forbids deleting the real head; therefore the maximum
// authentic serial is the true latest state and cannot be rolled back short of
// forging a KMS witness signature or removing a Google-enforced retention lock.
export async function tryRestoreGovernanceFromCapsule({ now = new Date() } = {}) {
  if (capsuleRestoreAttempted) return null;
  capsuleRestoreAttempted = true;
  const current = getGovernanceState();
  if (current.status !== INACTIVE || current.lineage.length > 0) {
    return null;
  }
  if (current.keyMaterial.kind !== "kms-backed") {
    return null;
  }

  const verified = await scanVerifiedCapsules({ now, current });
  if (verified.length === 0) {
    console.info("[governance] capsule restore: no authentic capsule for this image + KMS key in the bucket; starting inactive");
    return null;
  }
  // Highest authentic serial = true head (retention lock forbids deleting it).
  const winner = verified[0];
  const persistableState = winner.persistableState;

  // Observability: a latest-pointer naming a strictly-lower serial than the true
  // head is the fingerprint of a rollback attempt (or a lagged pointer write).
  try {
    const pointer = await readLatestPointer();
    if (pointer && Number.isInteger(pointer.capsuleSerial) && pointer.capsuleSerial < winner.serial) {
      console.warn(`[governance] capsule restore: latest-pointer names serial ${pointer.capsuleSerial} but the highest authentic capsule is serial ${winner.serial}; ignoring the pointer (possible rollback attempt or lagged write)`);
    }
  } catch (error) {
    console.warn("[governance] capsule restore: latest-pointer read failed (non-fatal; pointer is advisory):", error.message);
  }

  current.status = persistableState.status === "retired" ? RETIRED
    : persistableState.status === "activating_successor" ? ACTIVATING_SUCCESSOR
    : ACTIVE;
  current.epoch = persistableState.epoch;
  current.lineage = persistableState.lineage;
  current.latestPreapproval = persistableState.latestPreapproval || null;
  current.latestSuccessorCertificate = persistableState.latestSuccessorCertificate || null;
  current.latestRetirementCertificate = persistableState.latestRetirementCertificate || null;
  current.transferredState = persistableState.transferredState || {
    schema: "femled.tee.governance.transferred_state.v1",
    routePolicy: emptyRoutePolicyState(),
  };
  capsuleSerial = winner.serial;
  capsuleSerialBaselineEstablished = true;
  console.info(`[governance] capsule restore: restored ${current.status} governance at epoch ${current.epoch} from capsule serial ${winner.serial} (${winner.capsuleDigest}); ${verified.length} authentic capsule(s) considered`);

  return {
    restored: true,
    capsuleDigest: winner.capsuleDigest,
    status: current.status,
    epoch: current.epoch,
    capsuleSerial: winner.serial,
  };
}

// Enumerate the bucket and return every AUTHENTIC, restorable capsule with its
// witness-signed serial + decrypted state, sorted by serial descending. A
// capsule qualifies only if it decrypts under our KMS public key (proving the
// TEE itself sealed it) AND binds to this image + KMS key version + governance
// public key AND carries a valid predecessor-signed lineage whose active key is
// our KMS-bound key. The mutable latest-pointer is deliberately NOT consulted.
async function scanVerifiedCapsules({ now, current }) {
  let digests;
  try {
    digests = await listCapsuleObjects();
  } catch (error) {
    console.error("[governance] capsule restore: bucket enumeration failed:", error.message);
    return [];
  }
  if (digests.length > MAX_CAPSULES_SCANNED) {
    console.warn(`[governance] capsule restore: bucket holds ${digests.length} capsule objects (> ${MAX_CAPSULES_SCANNED}); scanning the first ${MAX_CAPSULES_SCANNED} (possible decoy flood by a hostile bucket owner)`);
    digests = digests.slice(0, MAX_CAPSULES_SCANNED);
  }
  const kmsPublicKeyPem = await current.keyMaterial.getKmsPublicKeyPem();
  const verified = [];
  for (const capsuleDigest of digests) {
    let capsule;
    try {
      capsule = await readStateCapsule(capsuleDigest);
    } catch (error) {
      console.warn(`[governance] capsule restore: skipping unreadable capsule ${capsuleDigest}: ${error.message}`);
      continue;
    }
    let persistableState;
    try {
      // Verifies the KMS witness signature over the AAD + the AES-GCM auth tag.
      // A forged or tampered capsule (or one sealed under a different key) fails
      // here and is skipped -- the bucket is untrusted.
      persistableState = decryptStateCapsule({ capsule, kmsPublicKeyPem });
    } catch {
      continue;
    }
    const serial = capsule?.aad?.capsuleSerial;
    if (!Number.isInteger(serial) || serial < 0) continue;
    if (!isRestorableGovernanceState({ persistableState, current, now })) continue;
    verified.push({ capsuleDigest, serial, persistableState });
  }
  verified.sort((a, b) => b.serial - a.serial);
  return verified;
}

// True when a decrypted capsule state binds to this running image + KMS key +
// governance public key AND its lineage verifies with the ACTIVE key equal to
// our KMS-bound key. We check the lineage's ACTIVE key (verifyLineage's
// currentGovernancePublicKeyPem), NOT the lineage TAIL's signingKeyId: a
// successor certificate is signed by the PREDECESSOR and only NAMES the new
// active key, so once the broker has activated past genesis the tail signer is
// never the current key (checking it falsely refused every legitimate
// successor-activated state).
function isRestorableGovernanceState({ persistableState, current, now }) {
  if (persistableState?.schema !== PERSISTABLE_STATE_SCHEMA) return false;
  if (persistableState.imageDigest !== current.imageDigest) return false;
  if (persistableState.governanceKmsKeyVersion !== current.keyMaterial.kmsKeyVersion) return false;
  if (persistableState.governancePublicKeyPem !== current.keyMaterial.governancePublicKeyPem) return false;
  let verified;
  try {
    verified = verifyLineage(persistableState.lineage || [], { now, enforceTerminalExpiry: false });
  } catch {
    return false;
  }
  const activeGovernanceKeyId = `sha256:${publicKeyFingerprint(verified.currentGovernancePublicKeyPem)}`;
  return activeGovernanceKeyId === current.keyMaterial.governanceKeyId
    && verified.currentGovernancePublicKeyPem === current.keyMaterial.governancePublicKeyPem;
}

// The highest authentic capsule serial already in the bucket for this image +
// KMS key, or 0 if none. Used to seed a fresh genesis / re-genesis above any
// abandoned lineage so it strictly supersedes it under highest-serial-wins.
async function maxVerifiedCapsuleSerial({ now, current }) {
  const verified = await scanVerifiedCapsules({ now, current });
  return verified.length > 0 ? verified[0].serial : 0;
}

// Retry hook for the boot-time fail-closed path. When KMS-backed governance key
// init failed at boot, initializeGovernanceAsync keeps an inactive in-memory
// shell (kmsUnavailable=true) and never activates/restores with it. This
// re-attempts KMS key init on the periodic refresh loop; on success it swaps in
// the KMS-backed key material, re-arms the one-shot restore guard, and re-runs
// the capsule restore -- so a transient Cloud KMS outage self-heals without
// operator action or a re-genesis. No-op once governance is active, when KMS was
// healthy at boot, or when KMS is still unavailable.
export async function retryGovernanceRestoreIfDegraded({ now = new Date(), createKeyMaterial = createKmsBackedGovernanceKeyMaterial } = {}) {
  if (!state || !kmsUnavailable) return null;
  if (state.status !== INACTIVE || state.lineage.length > 0) return null;
  if (!isKmsGovernanceKeyConfigured()) return null;
  let keyMaterial;
  try {
    keyMaterial = await createKeyMaterial();
  } catch (error) {
    console.error("[governance] KMS retry still failing; remaining inactive:", error.message);
    return null;
  }
  state.keyMaterial = keyMaterial;
  kmsUnavailable = false;
  // Re-arm the one-shot guard so the restore skipped at boot can run now that
  // we hold the KMS-bound governance key.
  capsuleRestoreAttempted = false;
  console.info("[governance] KMS recovered; re-attempting governance capsule restore");
  try {
    return await tryRestoreGovernanceFromCapsule({ now });
  } catch (error) {
    console.error("[governance] capsule restore retry failed; remaining inactive:", error.message);
    return null;
  }
}

// Periodic heartbeat: re-seal a fresh (higher-serial) capsule during quiet
// periods so the true head never ages out of the bucket's retention window. If
// the newest real capsule were allowed to age out and be deleted, cold-start
// "highest authentic serial wins" could silently fall back to an older
// still-present capsule -- a rollback. Hooked into the attestation refresh loop
// (server.js). Rate-limited to GOVERNANCE_CAPSULE_HEARTBEAT_MS (default 24h),
// well inside the retention window. No-op unless governance is active and
// persistence is configured.
export async function governanceCapsuleHeartbeatIfDue({ now = new Date() } = {}) {
  if (!isGovernancePersistenceEnabled()) return null;
  if (getGovernanceState().status !== ACTIVE) return null;
  const intervalMs = Number(process.env.GOVERNANCE_CAPSULE_HEARTBEAT_MS || 24 * 60 * 60 * 1000);
  if (lastCapsulePersistAt && (now.getTime() - lastCapsulePersistAt.getTime()) < intervalMs) {
    return null;
  }
  return persistGovernanceCapsuleBestEffort({ now });
}
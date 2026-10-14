import { canonicalStringify, publicKeyFingerprint, sha256Digest } from "./canonical-json.js";
import { getAttestedImageDigest, getAttestedImageReference, getLauncherAttestationClaims, getWifAccessToken } from "./gcp-auth.js";
import { requestAttestationToken } from "./attestation.js";
import { getRouteRegistryStatus } from "./route-registry.js";
import { createInMemoryGovernanceKeyMaterial, buildActivationNonce, verifyGovernanceEnvelope } from "./governance-crypto.js";
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
const GENESIS_SELF_ADJUDICATION_LIMIT = 8;

let state = null;

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
    genesisSelfAdjudications: new Map(),
    replicaRole: null,
    replicaSerial: 0,
    replicaPeer: null,
    transferredState: {
      schema: "femled.tee.governance.transferred_state.v1",
      routePolicy: emptyRoutePolicyState(),
    },
  };
  return state;
}

// Production cold start. The governance key is generated in this process and
// has no at-rest form, so a fresh boot is inactive until genesis, successor
// activation, or custody from a live replica of the same lineage.
export async function initializeGovernanceAsync({ mode = "inactive", keyMaterial = null, now = new Date() } = {}) {
  if (state) return state;
  return initializeGovernance({ mode, keyMaterial, now });
}

export function resetGovernanceForTests(nextState = null) {
  state = nextState;
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
  if (current.replicaRole === "custodian") {
    // A custodian holds the lineage key but serves nothing until promoted.
    if (pathname === "/health" || pathname === "/attestation" || pathname === "/.well-known/femled-tee-governance.json") return true;
    recordRouteGateDenied({ pathname });
    return false;
  }
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
  await withGovernanceCommit(() => {
    current.latestPreapproval = envelope;
  });
  recordPreapproval({ status: "issued", candidateDigest: candidate.candidateImageDigest });
  return envelope;
}

// Active governance must sign with key material generated inside this enclave.
// A signer held outside it (a Cloud KMS key) can be used directly by whoever
// administers the project, so production refuses to establish governance on one.
function assertEnclaveGovernanceKeyInProduction(current) {
  if (process.env.NODE_ENV === "production" && current.keyMaterial.kind !== "in-memory") {
    throw new Error("refusing to establish active governance with key material held outside the enclave");
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
  assertEnclaveGovernanceKeyInProduction(current);
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
  // Operator-authorized self-attested re-genesis is the only genesis path: the
  // candidate adjudicates the diff that produced its own image while INACTIVE.
  // It accepts only an approval this process produced and recorded. An
  // attestation over a caller-supplied payload proves nothing on its own,
  // because /attestation attests any nonce a caller asks for. Continuity IS
  // broken: the new lineage is not trusted by tenants until they re-admit it.
  const recordedExpiry = current.genesisSelfAdjudications?.get(payloadDigest);
  if (recordedExpiry === undefined) {
    throw new Error("genesis bootstrap accepts only an adjudication this TEE produced for its own genesis");
  }
  const reviewerAttestation = await verifyAttestation(response.attestationToken, {
    expectedNonce: payloadDigest,
  });
  const reviewerImageDigest = reviewerAttestation.submods?.container?.image_digest || null;
  if (reviewerImageDigest !== current.imageDigest) {
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

  await withGovernanceCommit(() => {
    if (current.status !== INACTIVE || current.lineage.length > 0) {
      throw new Error("genesis bootstrap requires a fresh inactive TEE");
    }
    current.status = ACTIVE;
    current.epoch = 1;
    current.lineage = [genesisCertificate];
  });
  current.genesisSelfAdjudications?.clear();

  return buildGovernanceManifestPayload();
}

// Records an APPROVE adjudication this INACTIVE TEE produced for its own
// genesis (operator-genesis.yml self-adjudication), the only approval
// bootstrapGenesisFromAttestedApproval will accept.
export function recordGenesisSelfAdjudication({ payloadDigest, expiresAt = null }) {
  const current = getGovernanceState();
  if (current.status !== INACTIVE || current.lineage.length > 0) return false;
  current.genesisSelfAdjudications ||= new Map();
  current.genesisSelfAdjudications.set(payloadDigest, expiresAt);
  while (current.genesisSelfAdjudications.size > GENESIS_SELF_ADJUDICATION_LIMIT) {
    current.genesisSelfAdjudications.delete(current.genesisSelfAdjudications.keys().next().value);
  }
  return true;
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
  await withGovernanceCommit(() => {
    assertActiveGovernance();
    if (sha256Digest(canonicalStringify(current.lineage)) !== lineageDigest) {
      throw new Error("governance lineage changed while the tenant admission was being issued");
    }
    assertTenantAdmissionDoesNotReplaceExistingKey(current, { tenant, tenantRouteSigningKeys });
    recordTenantAdmissionInState(envelope.payload, envelope.payloadDigest);
  });
  return envelope;
}

export function verifyTenantAdmissionEnvelope(envelope, { now = new Date() } = {}) {
  const current = getGovernanceState();
  // An admission is valid only under the lineage that issued it: its lineage
  // digest must be this lineage's prefix at its epoch, and it must be signed by
  // that epoch's key. A key reused across lineages therefore cannot carry an
  // admission from one lineage into another.
  const epoch = envelope?.payload?.governanceEpoch;
  if (!Number.isInteger(epoch) || epoch < 1 || epoch > current.lineage.length) {
    throw new Error("tenant admission epoch is not in the accepted governance lineage");
  }
  const prefixDigest = sha256Digest(canonicalStringify(current.lineage.slice(0, epoch)));
  if (envelope.payload.governanceLineageDigest !== prefixDigest) {
    throw new Error("tenant admission was not issued under the accepted governance lineage");
  }
  const epochKey = governanceKeyAtEpoch(current.lineage, epoch);
  if (!epochKey.publicKeyPem || envelope.signingKeyId !== epochKey.keyId) {
    throw new Error("tenant admission is not signed by the governance key of its epoch");
  }
  const payload = verifyGovernanceEnvelope(envelope, epochKey.publicKeyPem, { now });
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
    // Informational: route rollback is refused on the signed admission's
    // minRouteVersion, so this reaches the custodian in the background.
    notifyGovernanceStateChanged({ replicated: false });
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
  assertEnclaveGovernanceKeyInProduction(current);
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

  const { successorCertificate, encryptedState } = await withGovernanceCommit(async () => {
    assertActiveGovernance();
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
    return { successorCertificate, encryptedState };
  });

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
  assertEnclaveGovernanceKeyInProduction(current);
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
  await withGovernanceCommit(() => {
    if (current.status !== INACTIVE || current.lineage.length > 0) {
      throw new Error("activation bundle can only be applied to inactive candidate");
    }
    current.status = ACTIVE;
    current.epoch = transferred.epoch;
    current.lineage = transferred.lineage;
    current.transferredState = normalizeTransferredState(transferred.transferredState);
    current.latestSuccessorCertificate = successorCertificate;
  });
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
  const retirementCertificate = await withGovernanceCommit(async () => {
    if (current.status !== ACTIVATING_SUCCESSOR
      || current.pendingSuccessorActivation?.successorPayloadDigest !== pending.successorPayloadDigest) {
      throw new Error("pending successor activation changed before finalize");
    }
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
    current.pendingSuccessorActivation = null;
    return retirementCertificate;
  });
  current.pendingActivationChallenges.clear();
  recordActivation({ status: "success", candidateDigest: pending.candidateImageDigest });
  recordRetirement({ successorDigest: pending.successorPayloadDigest });
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
    replica: {
      role: current.replicaRole || null,
      serial: current.replicaSerial || 0,
      peer: current.replicaPeer
        ? { instanceName: current.replicaPeer.instanceName || null, role: current.replicaPeer.role || null }
        : null,
      health: {
        lastAcknowledgedAt: current.replicaHealth?.lastAcknowledgedAt || null,
        peerSerial: current.replicaHealth?.peerSerial ?? null,
        lastPrimaryContactAt: current.replicaHealth?.lastPrimaryContactAt || null,
        lastError: current.replicaHealth?.lastError || null,
      },
    },
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

// The governance key that was current at `epoch`: the genesis key for epoch 1,
// otherwise the key named by the successor certificate that opened the epoch.
function governanceKeyAtEpoch(lineage, epoch) {
  const payload = lineage[epoch - 1]?.payload || {};
  if (epoch === 1) {
    return payload.epoch === 1
      ? { keyId: payload.governanceKeyId, publicKeyPem: payload.governancePublicKeyPem }
      : {};
  }
  return payload.successorEpoch === epoch
    ? { keyId: payload.successorGovernanceKeyId, publicKeyPem: payload.successorGovernancePublicKeyPem }
    : {};
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

// Governance state lives only in this process (and its custodian replica's).
const governanceStateListeners = new Set();
let governanceStateReplicator = null;

export function onGovernanceStateChange(listener) {
  governanceStateListeners.add(listener);
  return () => governanceStateListeners.delete(listener);
}

// `replicated` is false for bookkeeping that changed without a commit and
// still has to reach the custodian.
function notifyGovernanceStateChanged({ replicated = true } = {}) {
  for (const listener of governanceStateListeners) {
    try {
      listener(getGovernanceState(), { replicated });
    } catch (error) {
      console.error("[governance] state-change listener failed:", error.message);
    }
  }
}

export function setGovernanceStateReplicator(replicator) {
  governanceStateReplicator = replicator;
}

function withGovernanceLock(fn) {
  const current = getGovernanceState();
  const run = (current.governanceQueue || Promise.resolve()).then(() => fn(current));
  current.governanceQueue = run.catch(() => {});
  return run;
}

// A change becomes visible outside this process (a signed certificate, a new
// status) only after the custodian has acknowledged it, and is reverted if it
// was not; a replica re-keyed from its custodian therefore never loses
// anything that was released. Serials never repeat, even after a revert, so a
// custodian that applied a change whose acknowledgement was lost still accepts
// the next one.
function withGovernanceCommit(mutate) {
  return withGovernanceLock(async (current) => {
    const previous = structuredClone(exportReplicaSnapshot(current));
    const serial = previous.replicaSerial + 1;
    let result;
    try {
      result = await mutate(current);
      current.replicaSerial = serial;
      if (governanceStateReplicator) await governanceStateReplicator(current);
    } catch (error) {
      applyReplicaSnapshot(current, previous);
      current.replicaSerial = serial;
      throw error;
    }
    notifyGovernanceStateChanged();
    return result;
  });
}

// Replicates bookkeeping that changed outside a commit.
export function replicateGovernanceState() {
  return withGovernanceCommit(() => {});
}

// ---------------------------------------------------------------------------
// Replica custody state. Two replicas of the same image hold one lineage key:
// the primary serves, the custodian keeps a current copy so a restarted replica
// can be re-keyed. Transfers are sealed to an attested replica's activation key
// (governance-replica-custody.js); nothing here is ever persisted.
// ---------------------------------------------------------------------------

const REPLICA_SNAPSHOT_SCHEMA = "femled.tee.governance.replica_snapshot.v1";
const REPLICA_ROLES = new Set(["primary", "custodian"]);

export function getReplicaRole() {
  return getGovernanceState().replicaRole || null;
}

export function setReplicaRole(role) {
  if (role !== null && !REPLICA_ROLES.has(role)) throw new Error(`unknown replica role ${role}`);
  getGovernanceState().replicaRole = role;
}

export function getReplicaPeer() {
  return getGovernanceState().replicaPeer || null;
}

export function recordReplicaPeer(peer) {
  getGovernanceState().replicaPeer = peer ? { ...peer, recordedAt: new Date().toISOString() } : null;
}

export function isGovernanceKeyHolder() {
  const status = getGovernanceState().status;
  return status === ACTIVE || status === ACTIVATING_SUCCESSOR;
}

function exportReplicaSnapshot(current) {
  return {
    schema: REPLICA_SNAPSHOT_SCHEMA,
    status: current.status,
    epoch: current.epoch,
    lineage: current.lineage,
    transferredState: current.transferredState,
    latestPreapproval: current.latestPreapproval,
    latestSuccessorCertificate: current.latestSuccessorCertificate,
    latestRetirementCertificate: current.latestRetirementCertificate,
    pendingSuccessorActivation: current.pendingSuccessorActivation,
    replicaSerial: current.replicaSerial || 0,
  };
}

function verifyReplicaSnapshot(snapshot, { now }) {
  if (snapshot?.schema !== REPLICA_SNAPSHOT_SCHEMA) throw new Error("replica snapshot schema mismatch");
  if (![ACTIVE, ACTIVATING_SUCCESSOR, RETIRED].includes(snapshot.status)) {
    throw new Error(`replica snapshot has unexpected status ${snapshot.status}`);
  }
  const verified = verifyLineage(snapshot.lineage, { now, enforceTerminalExpiry: false });
  if (verified.currentEpoch !== snapshot.epoch) throw new Error("replica snapshot epoch does not match its lineage");
  return verified;
}

function applyReplicaSnapshot(current, snapshot) {
  current.status = snapshot.status;
  current.epoch = snapshot.epoch;
  current.lineage = snapshot.lineage;
  current.transferredState = normalizeTransferredState(snapshot.transferredState || {});
  current.latestPreapproval = snapshot.latestPreapproval || null;
  current.latestSuccessorCertificate = snapshot.latestSuccessorCertificate || null;
  current.latestRetirementCertificate = snapshot.latestRetirementCertificate || null;
  current.pendingSuccessorActivation = snapshot.pendingSuccessorActivation || null;
  current.replicaSerial = snapshot.replicaSerial || 0;
}

// Sender side of custody: seals the lineage key and current state to a replica
// whose activation key the caller has verified through key-bound attestation.
export function buildReplicaCustodyTransfer({ recipientActivationPublicKeyPem, aad }) {
  return withGovernanceLock((current) => {
    if (!isGovernanceKeyHolder()) throw new Error(`replica custody requires a live lineage key holder, got ${current.status}`);
    assertEnclaveGovernanceKeyInProduction(current);
    return current.keyMaterial.encryptCustodyTransferFor(recipientActivationPublicKeyPem, exportReplicaSnapshot(current), aad);
  });
}

// Recipient side of custody: only a fresh inactive replica accepts it, and the
// transferred key must be the key the lineage currently names.
export function applyReplicaCustodyTransfer({ encryptedState, aad, role, expectedGovernanceKeyId, now = new Date() }) {
  return withGovernanceLock((current) => {
    if (current.status !== INACTIVE || current.lineage.length > 0) {
      throw new Error("replica custody can only be applied by a fresh inactive replica");
    }
    if (!REPLICA_ROLES.has(role)) throw new Error(`unknown replica role ${role}`);
    const { keyMaterial, state: snapshot } = current.keyMaterial.acceptCustodyTransfer(encryptedState, aad);
    if (keyMaterial.governanceKeyId !== expectedGovernanceKeyId) {
      throw new Error("replica custody key is not the sender's attested key");
    }
    const verified = verifyReplicaSnapshot(snapshot, { now });
    if (`sha256:${publicKeyFingerprint(verified.currentGovernancePublicKeyPem)}` !== keyMaterial.governanceKeyId) {
      throw new Error("replica custody key is not the key the lineage names");
    }
    if (sha256Digest(canonicalStringify(snapshot.lineage)) !== aad.lineageDigest) {
      throw new Error("replica custody lineage does not match its binding");
    }
    current.keyMaterial = keyMaterial;
    applyReplicaSnapshot(current, snapshot);
    current.replicaRole = role;
    current.pendingActivationChallenges.clear();
    return buildGovernanceManifestPayload();
  });
}

// Primary side of state sync, called by the replicator inside a commit: the
// custodian already holds the key, so only the state travels, encrypted to the
// custodian's attested activation key.
export function buildReplicaSync({ recipientActivationPublicKeyPem, aad }) {
  const current = getGovernanceState();
  return current.keyMaterial.encryptStateFor(recipientActivationPublicKeyPem, exportReplicaSnapshot(current), aad);
}

// Custodian side of state sync: only newer state that extends the custodian's
// own lineage is applied, including a retirement or a change after one.
export function applyReplicaSync({ encryptedState, aad, now = new Date() }) {
  return withGovernanceLock((current) => {
    if (current.replicaRole !== "custodian") throw new Error("only a custodian applies replica state sync");
    if (![ACTIVE, ACTIVATING_SUCCESSOR, RETIRED].includes(current.status)) {
      throw new Error(`replica sync requires a custodian holding the lineage, got ${current.status}`);
    }
    const snapshot = current.keyMaterial.decryptState(encryptedState, aad);
    verifyReplicaSnapshot(snapshot, { now });
    if ((snapshot.replicaSerial || 0) <= (current.replicaSerial || 0)) {
      throw new Error("replica sync is not newer than the custodian's state");
    }
    const ownLineageDigest = sha256Digest(canonicalStringify(current.lineage));
    const prefixDigest = sha256Digest(canonicalStringify(snapshot.lineage.slice(0, current.lineage.length)));
    if (snapshot.lineage.length < current.lineage.length || prefixDigest !== ownLineageDigest) {
      throw new Error("replica sync does not extend the custodian's lineage");
    }
    applyReplicaSnapshot(current, snapshot);
    return { status: current.status, epoch: current.epoch, replicaSerial: current.replicaSerial };
  });
}

// Promotion drops the old primary as peer: an old primary that is still alive
// can then commit nothing, because its syncs reach a replica that refuses them.
export function promoteReplicaToPrimary() {
  return withGovernanceLock((current) => {
    if (current.replicaRole !== "custodian") throw new Error("only a custodian can be promoted");
    if (current.status !== ACTIVE) throw new Error(`promotion requires active governance, got ${current.status}`);
    current.replicaRole = "primary";
    current.replicaPeer = null;
    return buildGovernanceManifestPayload();
  });
}

// Local custody health (never replicated): what this replica last heard from
// its peer, shown in the manifest so degraded custody is visible early.
export function recordReplicaHealth(patch) {
  const current = getGovernanceState();
  current.replicaHealth = { ...(current.replicaHealth || {}), ...patch };
}

export function getReplicaHealth() {
  return getGovernanceState().replicaHealth || {};
}
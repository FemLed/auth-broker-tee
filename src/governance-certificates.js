import { canonicalStringify, sha256Digest } from "./canonical-json.js";
import { signGovernancePayload, verifyGovernanceEnvelope } from "./governance-crypto.js";
import {
  FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
  FIRST_PRINCIPLES_MODEL,
  FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
  FIRST_PRINCIPLES_POLICY_VERSION,
  FIRST_PRINCIPLES_PROMPT_DIGEST,
  FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST,
  FIRST_PRINCIPLES_VERTEX_LOCATION,
} from "./first-principles-review.js";

export const GENESIS_SCHEMA = "femled.tee.governance.genesis.v1";
export const PREAPPROVAL_SCHEMA = "femled.tee.governance.preapproval.v1";
export const SUCCESSOR_SCHEMA = "femled.tee.governance.successor.v1";
export const RETIREMENT_SCHEMA = "femled.tee.governance.retirement.v1";
export const SELF_HEALING_PROPOSAL_SCHEMA = "femled.tee.self_healing.proposal.v1";
export const ACTIVATION_PROOF_SCHEMA = "femled.tee.governance.activation_proof.v1";
export const TENANT_ADMISSION_SCHEMA = "femled.auth_broker.tenant_admission.v1";

export function signGenesisCertificate({
  keyMaterial,
  imageDigest,
  routeRegistryStatus,
  attestationDigest = null,
  genesisBootstrap = null,
  now = new Date(),
}) {
  const payload = {
    schema: GENESIS_SCHEMA,
    epoch: 1,
    governancePublicKeyPem: keyMaterial.governancePublicKeyPem,
    governanceKeyId: keyMaterial.governanceKeyId,
    activationPublicKeyPem: keyMaterial.activationPublicKeyPem,
    activationKeyId: keyMaterial.activationKeyId,
    imageDigest,
    policyVersion: FIRST_PRINCIPLES_POLICY_VERSION,
    firstPrinciplesPromptDigest: FIRST_PRINCIPLES_PROMPT_DIGEST,
    responseSchemaDigest: FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST,
    model: FIRST_PRINCIPLES_MODEL,
    vertexLocation: FIRST_PRINCIPLES_VERTEX_LOCATION,
    modelPolicyDigest: FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
    temperature: FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
    routeTrustAnchorsDigest: routeRegistryStatus?.trustAnchorsDigest || null,
    routeBundleDigest: routeRegistryStatus?.routeBundleDigest || null,
    genesisBootstrap,
    issuedAt: now.toISOString(),
    expiresAt: null,
    attestationDigest,
  };
  return signGovernancePayload(payload, keyMaterial);
}

export function signPreapprovalCertificate({
  keyMaterial,
  predecessorEpoch,
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
  ttlMs = 30 * 60 * 1000,
}) {
  if (aiDecision?.decision !== "APPROVE") {
    throw new Error("preapproval requires AI decision APPROVE");
  }
  if ((aiDecision.violatedPrinciples || []).length > 0) {
    throw new Error("preapproval requires no violated principles");
  }
  if (hardCheckResults?.status !== "passed") {
    throw new Error("preapproval requires hard checks to pass");
  }
  const payload = {
    schema: PREAPPROVAL_SCHEMA,
    predecessorEpoch,
    predecessorGovernanceKeyId: keyMaterial.governanceKeyId,
    candidateImageDigest: requireDigest(candidate.candidateImageDigest, "candidateImageDigest"),
    candidateImageReference: candidate.candidateImageReference || null,
    candidateSourceTreeDigest: requireDigest(candidate.candidateSourceTreeDigest, "candidateSourceTreeDigest"),
    candidateFilesystemDigest: requireDigest(candidate.candidateFilesystemDigest, "candidateFilesystemDigest"),
    candidateSourceStructureDigest: candidate.candidateSourceStructureDigest || null,
    candidatePolicyManifestDigest: candidate.candidatePolicyManifestDigest || null,
    candidatePromptDigest: candidate.candidatePromptDigest || null,
    candidateModelPolicyDigest: candidate.candidateModelPolicyDigest || null,
    candidateModelProbeDigest: candidate.candidateModelProbeDigest || null,
    candidateModelCatalogEvidenceDigest: candidate.candidateModelCatalogEvidenceDigest || null,
    candidateModelPolicyDiffDigest: candidate.candidateModelPolicyDiffDigest || null,
    candidateRouteTrustAnchorsDigest: candidate.candidateRouteTrustAnchorsDigest || null,
    selfHealingProposalDigest: candidate.selfHealingProposalDigest || null,
    candidateChangedFiles: Array.isArray(candidate.candidateChangedFiles) ? candidate.candidateChangedFiles : [],
    hardCheckResultsDigest: sha256Digest(canonicalStringify(hardCheckResults)),
    aiDecision: aiDecision.decision,
    aiReasoningDigest: aiResponseDigest || sha256Digest(aiDecision.reasoning || ""),
    violatedPrinciples: aiDecision.violatedPrinciples || [],
    remediation: aiDecision.remediation || [],
    governanceRiskLevel: aiDecision.governanceRiskLevel || "low",
    stateTransferRisk: aiDecision.stateTransferRisk || "low",
    model: FIRST_PRINCIPLES_MODEL,
    vertexLocation: FIRST_PRINCIPLES_VERTEX_LOCATION,
    firstPrinciplesPromptDigest: FIRST_PRINCIPLES_PROMPT_DIGEST,
    responseSchemaDigest: FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST,
    modelPolicyDigest: FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
    challengeDigest,
    requestDigest,
    authorizedCallerDigest,
    authorizedWorkflowRef,
    authorizedRunId,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    nonce,
  };
  return signGovernancePayload(payload, keyMaterial);
}

export function signSuccessorCertificate({
  keyMaterial,
  predecessorEpoch,
  successorEpoch,
  candidateImageDigest,
  candidateAttestationDigest,
  candidateAttestationNonce,
  preapprovalPayloadDigest,
  successorDecisionPacketDigest,
  successorArbitrationDigest,
  successorGovernancePublicKeyPem,
  successorGovernanceKeyId,
  successorActivationPublicKeyPem,
  modelPolicyDigest = FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
  now = new Date(),
  ttlMs = 10 * 60 * 1000,
}) {
  const payload = {
    schema: SUCCESSOR_SCHEMA,
    predecessorEpoch,
    successorEpoch,
    predecessorGovernanceKeyId: keyMaterial.governanceKeyId,
    successorGovernanceKeyId,
    successorGovernancePublicKeyPem,
    successorActivationPublicKeyPem,
    candidateImageDigest: requireDigest(candidateImageDigest, "candidateImageDigest"),
    candidateAttestationDigest: requireDigest(candidateAttestationDigest, "candidateAttestationDigest"),
    candidateAttestationNonce,
    preapprovalPayloadDigest: requireDigest(preapprovalPayloadDigest, "preapprovalPayloadDigest"),
    successorDecisionPacketDigest: requireDigest(successorDecisionPacketDigest, "successorDecisionPacketDigest"),
    successorArbitrationDigest: requireDigest(successorArbitrationDigest, "successorArbitrationDigest"),
    arbitrationPhase: "successor_acceptance",
    model: FIRST_PRINCIPLES_MODEL,
    vertexLocation: FIRST_PRINCIPLES_VERTEX_LOCATION,
    firstPrinciplesPromptDigest: FIRST_PRINCIPLES_PROMPT_DIGEST,
    responseSchemaDigest: FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST,
    modelPolicyDigest,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
  };
  return signGovernancePayload(payload, keyMaterial);
}

export function signSelfHealingProposalCertificate({
  keyMaterial,
  epoch,
  proposal,
  healthSnapshotDigest,
  internalEventDigests = [],
  industryTelemetryDigest = null,
  now = new Date(),
  ttlMs = 6 * 60 * 60 * 1000,
}) {
  const payload = {
    schema: SELF_HEALING_PROPOSAL_SCHEMA,
    proposalId: proposal.proposalId || cryptoSafeProposalId(proposal),
    type: proposal.type || "operational_repair",
    epoch,
    governanceKeyId: keyMaterial.governanceKeyId,
    problemStatement: String(proposal.problemStatement || "").slice(0, 2000),
    requestedChange: proposal.requestedChange || null,
    expectedCandidateEvidence: proposal.expectedCandidateEvidence || {},
    healthSnapshotDigest: requireDigest(healthSnapshotDigest, "healthSnapshotDigest"),
    internalEventDigests: internalEventDigests.map((digest) => requireDigest(digest, "internalEventDigest")),
    industryTelemetryDigest: industryTelemetryDigest ? requireDigest(industryTelemetryDigest, "industryTelemetryDigest") : null,
    modelPolicyDigest: FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
  };
  return signGovernancePayload(payload, keyMaterial);
}

export function signTenantAdmissionCertificate({
  keyMaterial,
  epoch,
  lineageDigest,
  tenant,
  tenantRouteSigningKeys,
  minRouteVersion,
  allowedApiHosts,
  allowedAppHosts,
  allowedBrokerAudiences,
  registrationProofDigest = null,
  now = new Date(),
  ttlMs = 90 * 24 * 60 * 60 * 1000,
}) {
  assertTenantAdmissionInput({
    tenant,
    tenantRouteSigningKeys,
    minRouteVersion,
    allowedApiHosts,
    allowedAppHosts,
    allowedBrokerAudiences,
  });
  const payload = {
    schema: TENANT_ADMISSION_SCHEMA,
    tenant,
    tenantRouteSigningKeys,
    minRouteVersion,
    allowedApiHosts,
    allowedAppHosts,
    allowedBrokerAudiences,
    governanceEpoch: epoch,
    governanceKeyId: keyMaterial.governanceKeyId,
    governanceLineageDigest: requireDigest(lineageDigest, "governanceLineageDigest"),
    registrationProofDigest: registrationProofDigest ? requireDigest(registrationProofDigest, "registrationProofDigest") : null,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
  };
  return signGovernancePayload(payload, keyMaterial);
}

export function signRetirementCertificate({
  keyMaterial,
  retiredEpoch,
  successorEpoch,
  successorGovernanceKeyId,
  successorPayloadDigest,
  reason = "successor_activated",
  now = new Date(),
}) {
  const payload = {
    schema: RETIREMENT_SCHEMA,
    retiredEpoch,
    retiredGovernanceKeyId: keyMaterial.governanceKeyId,
    successorEpoch,
    successorGovernanceKeyId,
    successorPayloadDigest: requireDigest(successorPayloadDigest, "successorPayloadDigest"),
    retiredAt: now.toISOString(),
    reason,
  };
  return signGovernancePayload(payload, keyMaterial);
}

export function signActivationProofCertificate({
  keyMaterial,
  epoch,
  successorPayloadDigest,
  activationNonce,
  candidateImageDigest,
  lineageDigest,
  now = new Date(),
}) {
  const payload = {
    schema: ACTIVATION_PROOF_SCHEMA,
    epoch,
    governanceKeyId: keyMaterial.governanceKeyId,
    successorPayloadDigest: requireDigest(successorPayloadDigest, "successorPayloadDigest"),
    activationNonce,
    candidateImageDigest: requireDigest(candidateImageDigest, "candidateImageDigest"),
    lineageDigest: requireDigest(lineageDigest, "lineageDigest"),
    provedAt: now.toISOString(),
  };
  return signGovernancePayload(payload, keyMaterial);
}

export function assertTenantAdmissionPayload(payload, { now = new Date() } = {}) {
  if (payload?.schema !== TENANT_ADMISSION_SCHEMA) {
    throw new Error("expected tenant admission certificate");
  }
  assertTenantAdmissionInput(payload);
  requireDigest(payload.governanceLineageDigest, "governanceLineageDigest");
  if (!Number.isInteger(payload.governanceEpoch) || payload.governanceEpoch < 1) {
    throw new Error("tenant admission governanceEpoch must be a positive integer");
  }
  if (typeof payload.governanceKeyId !== "string" || !payload.governanceKeyId.startsWith("sha256:")) {
    throw new Error("tenant admission governanceKeyId must be a sha256 key id");
  }
  if (payload.registrationProofDigest !== null && payload.registrationProofDigest !== undefined) {
    requireDigest(payload.registrationProofDigest, "registrationProofDigest");
  }
  if (!Number.isFinite(Date.parse(payload.issuedAt))) {
    throw new Error("tenant admission issuedAt must be an ISO timestamp");
  }
  assertCertificateFresh(payload, { now, label: "tenant admission certificate" });
  return payload;
}

export function verifyLineage(lineage, { now = new Date(), enforceTerminalExpiry = false } = {}) {
  if (!Array.isArray(lineage) || lineage.length === 0) {
    throw new Error("governance lineage must contain genesis");
  }

  const verified = [];
  const genesis = verifyGovernanceEnvelope(lineage[0], lineage[0].payload?.governancePublicKeyPem, { now, enforceExpiry: false });
  if (genesis.schema !== GENESIS_SCHEMA || genesis.epoch !== 1) {
    throw new Error("governance lineage must start with genesis epoch 1");
  }
  verified.push(genesis);
  let currentPublicKeyPem = genesis.governancePublicKeyPem;
  let currentEpoch = genesis.epoch;

  for (let i = 1; i < lineage.length; i++) {
    const payload = verifyGovernanceEnvelope(lineage[i], currentPublicKeyPem, { now, enforceExpiry: false });
    if (payload.schema !== SUCCESSOR_SCHEMA) {
      throw new Error(`unexpected governance lineage schema ${payload.schema}`);
    }
    if (payload.predecessorEpoch !== currentEpoch || payload.successorEpoch !== currentEpoch + 1) {
      throw new Error("governance lineage epoch discontinuity");
    }
    verified.push(payload);
    currentEpoch = payload.successorEpoch;
    currentPublicKeyPem = payload.successorGovernancePublicKeyPem;
  }
  if (enforceTerminalExpiry) {
    assertCertificateFresh(lineage[lineage.length - 1]?.payload, { now });
  }

  return {
    currentEpoch,
    currentGovernancePublicKeyPem: currentPublicKeyPem,
    certificates: verified,
  };
}

export function assertCertificateFresh(payload, { now = new Date(), label = "governance certificate" } = {}) {
  if (payload?.expiresAt && Date.parse(payload.expiresAt) <= now.getTime()) {
    throw new Error(`${label} expired`);
  }
}

export function assertPreapprovalMatchesCandidate(preapprovalPayload, candidate) {
  if (preapprovalPayload.schema !== PREAPPROVAL_SCHEMA) {
    throw new Error("expected preapproval certificate");
  }
  for (const [key, value] of Object.entries({
    candidateImageDigest: candidate.candidateImageDigest,
    candidateSourceTreeDigest: candidate.candidateSourceTreeDigest,
    candidateFilesystemDigest: candidate.candidateFilesystemDigest,
    candidateSourceStructureDigest: candidate.candidateSourceStructureDigest,
    candidateModelProbeDigest: candidate.candidateModelProbeDigest,
    candidateModelCatalogEvidenceDigest: candidate.candidateModelCatalogEvidenceDigest,
    candidateModelPolicyDiffDigest: candidate.candidateModelPolicyDiffDigest,
  })) {
    if (value && preapprovalPayload[key] !== value) {
      throw new Error(`preapproval ${key} mismatch`);
    }
  }
}

function assertTenantAdmissionInput({
  tenant,
  tenantRouteSigningKeys,
  minRouteVersion,
  allowedApiHosts,
  allowedAppHosts,
  allowedBrokerAudiences,
}) {
  if (typeof tenant !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenant)) {
    throw new Error("tenant admission tenant must be a UUID");
  }
  if (!Number.isInteger(minRouteVersion) || minRouteVersion < 1) {
    throw new Error("tenant admission minRouteVersion must be a positive integer");
  }
  assertStringArray(allowedApiHosts, "allowedApiHosts");
  assertStringArray(allowedAppHosts, "allowedAppHosts");
  assertStringArray(allowedBrokerAudiences, "allowedBrokerAudiences");
  if (!allowedBrokerAudiences.includes("https://oauth-tee.femled.ai")) {
    throw new Error("tenant admission allowedBrokerAudiences must include https://oauth-tee.femled.ai");
  }
  if (!Array.isArray(tenantRouteSigningKeys) || tenantRouteSigningKeys.length === 0) {
    throw new Error("tenant admission tenantRouteSigningKeys must be a non-empty array");
  }
  const seen = new Set();
  for (const key of tenantRouteSigningKeys) {
    if (!key || typeof key !== "object") throw new Error("tenant route signing key must be an object");
    if (!["Ed25519", "ECDSA_P256_SHA256"].includes(key.alg)) {
      throw new Error("tenant route signing key alg must be Ed25519 or ECDSA_P256_SHA256");
    }
    if (!key.keyId || typeof key.keyId !== "string") throw new Error("tenant route signing key needs keyId");
    if (seen.has(key.keyId)) throw new Error(`duplicate tenant route signing key ${key.keyId}`);
    seen.add(key.keyId);
    if (typeof key.publicKeyPem !== "string" || !key.publicKeyPem.includes("BEGIN PUBLIC KEY")) {
      throw new Error(`tenant route signing key ${key.keyId} must include publicKeyPem`);
    }
    if (key.fingerprint && !/^sha256:[a-f0-9]{64}$/i.test(key.fingerprint)) {
      throw new Error(`tenant route signing key ${key.keyId} fingerprint must be sha256:<hex>`);
    }
    if (key.kmsKeyVersion && typeof key.kmsKeyVersion !== "string") {
      throw new Error(`tenant route signing key ${key.keyId} kmsKeyVersion must be a string`);
    }
  }
}

function assertStringArray(value, name) {
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new Error(`tenant admission ${name} must be a non-empty string array`);
  }
}

function requireDigest(value, name) {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/i.test(value)) {
    throw new Error(`${name} must be a sha256 digest`);
  }
  return value;
}

function cryptoSafeProposalId(proposal) {
  return sha256Digest(canonicalStringify({
    type: proposal.type || "operational_repair",
    problemStatement: proposal.problemStatement || "",
    requestedChange: proposal.requestedChange || null,
  }));
}
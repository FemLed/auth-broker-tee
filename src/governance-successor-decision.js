import { canonicalStringify, sha256Digest } from "./canonical-json.js";

export const SUCCESSOR_DECISION_PACKET_SCHEMA = "femled.tee.governance.successor_decision_packet.v1";
export const SUCCESSOR_HARD_VETO_SCHEMA = "femled.tee.governance.successor_hard_veto.v1";

export function buildSuccessorDecisionPacket({
  currentManifest,
  candidate,
  preapprovalEnvelope,
  preapprovalPayload,
  candidateAttestationToken,
  candidateAttestation,
  candidateGovernanceKeyId,
  candidateGovernancePublicKeyPem,
  candidateActivationPublicKeyPem,
  activationNonce,
  expectedCandidateImageDigest,
  expectedActivationNonce,
  now = new Date(),
} = {}) {
  const packet = {
    schema: SUCCESSOR_DECISION_PACKET_SCHEMA,
    issuedAt: now.toISOString(),
    currentTee: summarizeCurrentTee(currentManifest),
    candidateTee: summarizeCandidateTee({
      candidate,
      candidateGovernanceKeyId,
      candidateGovernancePublicKeyPem,
      candidateActivationPublicKeyPem,
    }),
    activationEvidence: {
      schema: "femled.tee.governance.activation_evidence.v1",
      activationNonce,
      expectedActivationNonce,
      expectedCandidateImageDigest,
      candidateAttestationDigest: candidateAttestationToken ? sha256Digest(candidateAttestationToken) : null,
      candidateAttestation: summarizeAttestation(candidateAttestation),
    },
    preapprovalEvidence: {
      schema: "femled.tee.governance.preapproval_evidence.v1",
      preapprovalPayloadDigest: preapprovalEnvelope?.payloadDigest || null,
      preapprovalSigningKeyId: preapprovalEnvelope?.signingKeyId || null,
      preapprovalSchema: preapprovalPayload?.schema || null,
      predecessorEpoch: preapprovalPayload?.predecessorEpoch || null,
      predecessorGovernanceKeyId: preapprovalPayload?.predecessorGovernanceKeyId || null,
      hardCheckResultsDigest: preapprovalPayload?.hardCheckResultsDigest || null,
      aiDecision: preapprovalPayload?.aiDecision || null,
      aiReasoningDigest: preapprovalPayload?.aiReasoningDigest || null,
      modelPolicyDigest: preapprovalPayload?.modelPolicyDigest || null,
      expiresAt: preapprovalPayload?.expiresAt || null,
    },
    evidenceCompleteness: summarizeEvidenceCompleteness(candidate),
    supplyChainEvidence: summarizeSupplyChainEvidence(candidate),
    selfHealingEvidence: summarizeSelfHealingEvidence(currentManifest, candidate),
  };
  return {
    packet,
    packetDigest: sha256Digest(canonicalStringify(packet)),
  };
}

export function evaluateSuccessorHardVetoes(packet) {
  const failures = [];
  const warnings = [];
  if (packet?.schema !== SUCCESSOR_DECISION_PACKET_SCHEMA) {
    failures.push("successor decision packet schema mismatch");
  }
  if (packet?.currentTee?.status !== "active") {
    failures.push(`current TEE must be active, got ${packet?.currentTee?.status || "unknown"}`);
  }
  if (!packet?.currentTee?.lineageDigest) {
    failures.push("current TEE lineage digest is missing");
  }
  if (packet?.candidateTee?.imageDigest !== packet?.activationEvidence?.expectedCandidateImageDigest) {
    failures.push("candidate image digest does not match activation expectation");
  }
  if (packet?.activationEvidence?.activationNonce !== packet?.activationEvidence?.expectedActivationNonce) {
    failures.push("activation nonce does not match attestation expectation");
  }
  if (packet?.activationEvidence?.candidateAttestation?.imageDigest !== packet?.candidateTee?.imageDigest) {
    failures.push("candidate attestation image digest does not match candidate image digest");
  }
  if (!nonceMatches(packet?.activationEvidence?.candidateAttestation?.eatNonce, packet?.activationEvidence?.activationNonce)) {
    failures.push("candidate attestation nonce does not bind activation challenge");
  }
  if (packet?.activationEvidence?.candidateAttestation?.swname !== "CONFIDENTIAL_SPACE") {
    failures.push("candidate attestation is not Confidential Space");
  }
  if (packet?.activationEvidence?.candidateAttestation?.dbgstat !== "disabled-since-boot") {
    failures.push("candidate attestation debug status is not disabled-since-boot");
  }
  if (packet?.candidateTee?.hardCheckStatus !== "passed") {
    failures.push(`candidate hard checks must pass, got ${packet?.candidateTee?.hardCheckStatus || "unknown"}`);
  }
  if (packet?.evidenceCompleteness?.criticalSourceStatus !== "complete") {
    failures.push("governance-critical source evidence is incomplete");
  }
  if (!packet?.candidateTee?.governanceKeyId || !packet?.candidateTee?.activationPublicKeyPem) {
    failures.push("candidate governance and activation keys must be present");
  }
  if (packet?.preapprovalEvidence?.aiDecision !== "APPROVE") {
    failures.push("preapproval Gemini decision must be APPROVE");
  }
  if (packet?.preapprovalEvidence?.predecessorEpoch !== packet?.currentTee?.epoch) {
    failures.push("preapproval predecessor epoch does not match current TEE epoch");
  }
  if (packet?.preapprovalEvidence?.predecessorGovernanceKeyId !== packet?.currentTee?.governanceKeyId) {
    failures.push("preapproval predecessor key does not match current TEE key");
  }
  if (packet?.supplyChainEvidence?.complianceSummaryPresent === false) {
    warnings.push("candidate compliance summary body is not present in decision packet");
  }
  return {
    schema: SUCCESSOR_HARD_VETO_SCHEMA,
    status: failures.length === 0 ? "passed" : "failed",
    failures,
    warnings,
    checkedAt: new Date().toISOString(),
  };
}

export function digestSuccessorDecisionPacket(packet) {
  return sha256Digest(canonicalStringify(packet));
}

function summarizeCurrentTee(manifest = {}) {
  return {
    schema: "femled.tee.governance.current_tee_summary.v1",
    status: manifest.status || null,
    epoch: manifest.epoch || 0,
    governanceKeyId: manifest.governanceKeyId || null,
    activationKeyId: manifest.activationKeyId || null,
    imageDigest: manifest.imageDigest || null,
    lineageDigest: manifest.lineageDigest || null,
    latestSuccessorDigest: manifest.latestSuccessorCertificate?.payloadDigest || null,
    latestRetirementDigest: manifest.latestRetirementCertificate?.payloadDigest || null,
    routeTrustAnchorsDigest: manifest.routeTrustAnchorsDigest || null,
    routeBundleDigest: manifest.routeBundleDigest || null,
    modelPolicyDigest: manifest.modelPolicyDigest || null,
    health: manifest.health || null,
    securityBoundary: manifest.securityBoundary || null,
  };
}

function summarizeCandidateTee({
  candidate = {},
  candidateGovernanceKeyId,
  candidateGovernancePublicKeyPem,
  candidateActivationPublicKeyPem,
}) {
  return {
    schema: "femled.tee.governance.candidate_tee_summary.v1",
    imageDigest: candidate.candidateImageDigest || null,
    imageReference: candidate.candidateImageReference || null,
    manifestDigest: candidate.candidateManifestDigest || null,
    sourceTreeDigest: candidate.candidateSourceTreeDigest || null,
    filesystemDigest: candidate.candidateFilesystemDigest || null,
    sourceStructureDigest: candidate.candidateSourceStructureDigest || null,
    policyManifestDigest: candidate.candidatePolicyManifestDigest || null,
    promptDigest: candidate.candidatePromptDigest || null,
    modelPolicyDigest: candidate.candidateModelPolicyDigest || null,
    modelProbeDigest: candidate.candidateModelProbeDigest || null,
    modelPolicyDiffDigest: candidate.candidateModelPolicyDiffDigest || null,
    routeTrustAnchorsDigest: candidate.candidateRouteTrustAnchorsDigest || null,
    changedFiles: candidate.candidateChangedFiles || [],
    sourceBundleDigest: candidate.sourceBundleDigest || null,
    hardCheckStatus: candidate.hardCheckResults?.status || null,
    hardCheckFailures: candidate.hardCheckResults?.failures || [],
    hardCheckWarnings: candidate.hardCheckResults?.warnings || [],
    governanceKeyId: candidateGovernanceKeyId || null,
    governancePublicKeyPem: candidateGovernancePublicKeyPem || null,
    activationPublicKeyPem: candidateActivationPublicKeyPem || null,
    launchPolicy: summarizeLaunchPolicy(candidate.config),
  };
}

function summarizeEvidenceCompleteness(candidate = {}) {
  const completeness = candidate.criticalSourceCompleteness || {};
  return {
    schema: "femled.tee.governance.evidence_completeness.v1",
    criticalSourceStatus: completeness.status || "unknown",
    requiredCriticalFiles: completeness.requiredFiles || [],
    presentCriticalFiles: completeness.presentFiles || [],
    missingCriticalFiles: completeness.missingFiles || [],
    omittedFileCount: candidate.candidateSourceStructure?.omittedFileCount || 0,
    governanceCriticalParseFailures: candidate.candidateSourceStructure?.governanceCriticalParseFailures || [],
  };
}

function summarizeSupplyChainEvidence(candidate = {}) {
  const sourceBundle = candidate.sourceBundleEvidence || {};
  return {
    schema: "femled.tee.governance.supply_chain_evidence.v1",
    complianceRulesDigest: sourceBundle.complianceRulesDigest || candidate.complianceRulesDigest || null,
    complianceSummaryDigest: sourceBundle.complianceSummaryDigest || candidate.complianceSummaryDigest || null,
    complianceSummaryPresent: Boolean(sourceBundle.complianceSummary || candidate.complianceSummary),
    buildPredicateDigest: sourceBundle.buildPredicateDigest || candidate.buildPredicateDigest || null,
    provenanceDigest: sourceBundle.provenanceDigest || candidate.provenanceDigest || null,
    sourceImageBindingDigest: sourceBundle.sourceImageBindingDigest || candidate.sourceImageBindingDigest || null,
    imageSignatureDigest: sourceBundle.imageSignatureDigest || candidate.imageSignatureDigest || null,
    modelUpgradeEvidence: {
      schema: "femled.tee.governance.model_upgrade_evidence.v1",
      modelProbeDigest: sourceBundle.modelProbeDigest || candidate.candidateModelProbeDigest || null,
      modelCatalogEvidenceDigest: sourceBundle.modelCatalogEvidenceDigest || candidate.candidateModelCatalogEvidenceDigest || null,
      modelPolicyDiffDigest: sourceBundle.modelPolicyDiffDigest || candidate.candidateModelPolicyDiffDigest || null,
      authority: "model_upgrade_evidence_only_not_runtime_selection",
    },
  };
}

function summarizeSelfHealingEvidence(currentManifest = {}, candidate = {}) {
  const selfHealing = currentManifest.selfHealing || {};
  const proposalDigest = candidate.selfHealingProposalDigest || null;
  const openJobs = selfHealing.repairJobs?.openJobs || [];
  const relatedJobs = proposalDigest
    ? openJobs.filter((job) => job.proposalDigest === proposalDigest)
    : [];
  return {
    schema: "femled.tee.governance.self_healing_evidence.v1",
    proposalDigest,
    openProposalDigests: selfHealing.openProposalDigests || [],
    relatedRepairJobDigests: relatedJobs.map((job) => job.jobRequestDigest),
    relatedArtifactDigests: relatedJobs.flatMap((job) => [
      job.artifactDigest,
      job.candidateSubmissionDigest,
      ...(job.investigationArtifactDigests || []),
    ].filter(Boolean)),
    authority: "self_healing_evidence_only_not_activation",
  };
}

function summarizeAttestation(attestation = {}) {
  return {
    schema: "femled.tee.governance.candidate_attestation_summary.v1",
    imageDigest: attestation.submods?.container?.image_digest || null,
    imageReference: attestation.submods?.container?.image_reference || null,
    imageSignatures: attestation.submods?.container?.image_signatures || [],
    cmdOverride: attestation.submods?.container?.cmd_override || [],
    envOverrideKeys: Object.keys(attestation.submods?.container?.env_override || {}).sort(),
    swname: attestation.swname || null,
    dbgstat: attestation.dbgstat || null,
    eatNonce: attestation.eat_nonce || null,
    projectId: attestation.submods?.gce?.project_id || null,
    instanceId: attestation.submods?.gce?.instance_id || null,
  };
}

function summarizeLaunchPolicy(config = {}) {
  const labels = config?.config?.Labels || config?.Labels || {};
  return {
    schema: "femled.tee.governance.launch_policy_summary.v1",
    logRedirect: labels["tee.launch_policy.log_redirect"] || null,
    allowCmdOverride: labels["tee.launch_policy.allow_cmd_override"] || null,
    allowEnvOverride: labels["tee.launch_policy.allow_env_override"] || "",
  };
}

function nonceMatches(eatNonce, expected) {
  if (!expected) return false;
  if (Array.isArray(eatNonce)) return eatNonce.includes(expected);
  return eatNonce === expected;
}

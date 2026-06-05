import { canonicalStringify, sha256Digest } from "./canonical-json.js";
import { buildHealthSnapshot, recordRepairLaunch, recordSelfImprovement } from "./governance-monitor.js";
import { getGovernanceState, issueSelfHealingProposal } from "./governance-state.js";
import { createRepairJobForProposal, getRepairJobManifest } from "./governance-repair-jobs.js";
import { launchPendingRepairJobs } from "./governance-repair-launcher.js";
import { evaluateModelPolicyUpgradeOpportunity } from "./governance-model-policy-supervisor.js";

const DEFAULT_INTERVAL_MS = 60_000;
const SELF_IMPROVEMENT_SCHEMA = "femled.tee.self_improvement.trigger.v1";

let timer = null;

export function startSelfImprovementLoop({ intervalMs = Number(process.env.TEE_SELF_IMPROVEMENT_INTERVAL_MS || DEFAULT_INTERVAL_MS) } = {}) {
  if (timer || intervalMs <= 0) return;
  timer = setInterval(() => {
    evaluateSelfImprovementOnce().catch((error) => {
      console.error("[SelfImprovement] evaluation failed:", error.message);
    });
  }, intervalMs);
  evaluateSelfImprovementOnce().catch((error) => {
    console.error("[SelfImprovement] initial evaluation failed:", error.message);
  });
}

export function stopSelfImprovementLoopForTests() {
  if (timer) clearInterval(timer);
  timer = null;
}

export async function evaluateSelfImprovementOnce({ now = new Date(), modelPolicyUpgradeOptions = {} } = {}) {
  try {
    const current = getGovernanceState();
    if (current.status !== "active") {
      recordSelfImprovement({ status: "skipped" });
      return null;
    }
    getRepairJobManifest();
    const lineageDigest = sha256Digest(canonicalStringify(current.lineage));
    let health = buildHealthSnapshot({
      governanceStatus: current.status,
      epoch: current.epoch,
      lineageDigest,
    });
    try {
      const launched = await launchPendingRepairJobs();
      if (launched.length > 0) {
        recordRepairLaunch({ status: "success", launchedCount: launched.length });
        health = buildHealthSnapshot({
          governanceStatus: current.status,
          epoch: current.epoch,
          lineageDigest,
        });
      }
    } catch (error) {
      recordRepairLaunch({ status: "failed", error });
      console.error("[SelfImprovement] repair worker launch failed:", error.message);
    }
    const trigger = chooseTrigger(health);
    if (trigger) {
      const result = await createSelfHealingRepair({
        current,
        proposal: buildProposalForTrigger({ trigger, health, now }),
        health,
        now,
        internalEventDigests: [health.recentEventsDigest],
      });
      recordSelfImprovement({ status: "success", proposalType: result?.proposalEnvelope?.payload?.type || trigger.type });
      return result;
    }
    const modelPolicyOpportunity = await evaluateModelPolicyUpgradeOpportunity({
      current,
      health,
      now,
      ...modelPolicyUpgradeOptions,
    });
    if (!modelPolicyOpportunity?.proposal) {
      recordSelfImprovement({ status: "success" });
      return null;
    }
    const result = await createSelfHealingRepair({
      current,
      proposal: modelPolicyOpportunity.proposal,
      health,
      now,
      internalEventDigests: [health.recentEventsDigest, modelPolicyOpportunity.modelProbeDigest],
    });
    if (result?.proposalEnvelope) {
      current.modelPolicySupervisor.lastProposalDigest = result.proposalEnvelope.payloadDigest;
    }
    recordSelfImprovement({ status: "success", proposalType: result?.proposalEnvelope?.payload?.type || modelPolicyOpportunity.proposal.type });
    if (!result) return null;
    return {
      ...result,
      modelPolicyEvidence: modelPolicyOpportunity.evidence,
      modelProbeDigest: modelPolicyOpportunity.modelProbeDigest,
    };
  } catch (error) {
    recordSelfImprovement({ status: "failed", error });
    throw error;
  }
}

async function createSelfHealingRepair({ current, proposal, health, now, internalEventDigests }) {
  const problemDigest = sha256Digest(canonicalStringify({
    type: proposal.type,
    problemStatement: proposal.problemStatement,
    requestedChange: dedupeRequestedChange(proposal.requestedChange),
  }));
  if (hasLiveEquivalentProposal(current.selfHealingProposals, { type: proposal.type, problemDigest, now })) {
    return null;
  }
  const proposalEnvelope = await issueSelfHealingProposal({
    proposal: {
      ...proposal,
      proposalId: `repair:${problemDigest.slice("sha256:".length, "sha256:".length + 24)}`,
      expectedCandidateEvidence: {
        selfHealingProposalDigest: true,
        sourceBundleDigest: true,
        candidateImageDigest: true,
        buildSummaryDigest: true,
        testSummaryDigest: true,
        ...(proposal.expectedCandidateEvidence || {}),
      },
    },
    healthSnapshot: health,
    internalEventDigests,
    now,
  });
  const repairJob = createRepairJobForProposal({
    proposalEnvelope,
    healthSnapshot: health,
    requestedChange: proposal.requestedChange,
    now,
  });
  try {
    const launched = await launchPendingRepairJobs();
    recordRepairLaunch({ status: "success", launchedCount: launched.length });
  } catch (error) {
    recordRepairLaunch({ status: "failed", error });
    console.error("[SelfImprovement] repair worker launch failed:", error.message);
  }
  return { proposalEnvelope, repairJob, health };
}

function chooseTrigger(health) {
  const unresolved = health.unresolvedFailures || {};
  if (unresolved.vertexRetryExhausted || health.vertexCircuit?.open) {
    return { type: "vertex_repair", surface: "vertex", risk: "critical" };
  }
  if (unresolved.wif) {
    return { type: "wif_repair", surface: "wif", risk: "warning" };
  }
  if (unresolved.attestationRefresh || unresolved.attestationRefreshFailures >= 3) {
    return { type: "attestation_repair", surface: "attestation", risk: "critical" };
  }
  if (unresolved.routeBundleRefresh) {
    return { type: "route_registry_repair", surface: "route-registry", risk: "warning" };
  }
  if (unresolved.modelProbe) {
    return { type: "model_policy_repair", surface: "model-policy", risk: "warning" };
  }
  if (unresolved.selfImprovement) {
    return { type: "self_improvement_repair", surface: "self-improvement", risk: "warning" };
  }
  if (unresolved.repairLaunch || unresolved.staleRepairJobs) {
    return { type: "repair_worker_repair", surface: "repair-worker", risk: "warning" };
  }
  if (unresolved.manifestAttestation) {
    return { type: "manifest_attestation_repair", surface: "manifest-attestation", risk: "warning" };
  }
  if (unresolved.routeProof || unresolved.tokenDeposit || unresolved.tenantRouteLookup) {
    return { type: "tenant_contract_repair", surface: "tenant-contract", risk: "warning" };
  }
  if (unresolved.deployWebhook) {
    return { type: "deploy_webhook_repair", surface: "deploy-webhook", risk: "warning" };
  }
  return null;
}

function buildProposalForTrigger({ trigger, health, now }) {
  const requestedChange = {
    schema: SELF_IMPROVEMENT_SCHEMA,
    surface: trigger.surface,
    risk: trigger.risk,
    healthStatus: health.status,
    availabilityRisk: health.availabilityRisk,
    governanceRisk: health.governanceRisk,
    generatedAt: now.toISOString(),
    instructions: [
      "Inspect the relevant auth-broker-tee source paths.",
      "Produce a minimal source repair candidate and evidence bundle.",
      "Do not add any deployment, activation, key recovery, or governance authority path.",
    ],
  };
  return {
    type: trigger.type,
    problemStatement: `${trigger.surface} health signal is unresolved; build a minimal proposal-bound repair candidate.`,
    requestedChange,
  };
}

function hasLiveEquivalentProposal(proposals, { type, problemDigest, now }) {
  return (proposals || []).some((proposal) =>
    proposal.payload?.type === type &&
    sha256Digest(canonicalStringify({
      type: proposal.payload.type,
      problemStatement: proposal.payload.problemStatement,
      requestedChange: dedupeRequestedChange(proposal.payload.requestedChange),
    })) === problemDigest &&
    (!proposal.payload.expiresAt || Date.parse(proposal.payload.expiresAt) > now.getTime())
  );
}

function dedupeRequestedChange(requestedChange) {
  if (!requestedChange || typeof requestedChange !== "object") return requestedChange || null;
  const { generatedAt, modelProbeDigest, ...stable } = requestedChange;
  return stable;
}

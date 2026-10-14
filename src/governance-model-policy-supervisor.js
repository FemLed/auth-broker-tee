import { canonicalStringify, sha256Digest } from "./canonical-json.js";
import {
  FIRST_PRINCIPLES_MODEL,
  FIRST_PRINCIPLES_MODEL_POLICY,
} from "./first-principles-review.js";
import {
  listFirstPrinciplesModelCatalogCandidates,
  probeFirstPrinciplesModelCandidate,
} from "./vertex-gemini.js";

export const MODEL_POLICY_SCAN_SCHEMA = "femled.tee.model_policy.scan.v1";
export const MODEL_POLICY_UPGRADE_REQUEST_SCHEMA = "femled.tee.model_policy.upgrade_request.v1";
export const DEFAULT_MODEL_POLICY_SCAN_INTERVAL_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_MODEL_POLICY_PROBE_TIMEOUT_MS = 60_000;
const MODEL_POLICY_UPGRADE_REQUIRED_SOURCE_PATHS = [
  "src/first-principles-review.js",
  "repair-worker/repair-worker-run.py",
];

export async function evaluateModelPolicyUpgradeOpportunity({
  current,
  health,
  now = new Date(),
  scanIntervalMs = Number(process.env.TEE_MODEL_POLICY_SCAN_INTERVAL_MS || DEFAULT_MODEL_POLICY_SCAN_INTERVAL_MS),
  probeTimeoutMs = Number(process.env.TEE_MODEL_POLICY_PROBE_TIMEOUT_MS || DEFAULT_MODEL_POLICY_PROBE_TIMEOUT_MS),
  discoverModelCandidates = listFirstPrinciplesModelCatalogCandidates,
  probeModelCandidate = probeFirstPrinciplesModelCandidate,
} = {}) {
  if (current?.status !== "active") return null;
  const state = ensureModelPolicySupervisorState(current);
  state.lastEvaluationAt = now.toISOString();
  if (!shouldScan(state, { now, scanIntervalMs })) return null;

  state.lastScanStartedAt = now.toISOString();
  state.lastScanError = null;
  let catalogCandidates;
  try {
    catalogCandidates = await discoverModelCandidates();
  } catch (error) {
    state.lastScanError = buildPublicScanError({ stage: "catalog_discovery", error, now });
    throw error;
  }
  const candidates = strongerSuccessorCandidates(catalogCandidates);
  const probeResults = [];
  let selected = null;
  for (const candidate of candidates) {
    let result;
    try {
      result = await withTimeout(
        probeModelCandidate(candidate.model, { candidate, currentModel: FIRST_PRINCIPLES_MODEL }),
        probeTimeoutMs,
        `model probe timed out for ${candidate.model}`
      );
    } catch (error) {
      result = {
        status: "failed",
        model: candidate.model,
        reason: publicProbeFailureReason(error),
      };
    }
    const normalized = normalizeProbeResult(result, candidate);
    probeResults.push(normalized);
    if (!selected && normalized.status === "passed") {
      selected = normalized;
      break;
    }
  }

  const evidence = {
    schema: MODEL_POLICY_SCAN_SCHEMA,
    scannedAt: now.toISOString(),
    currentModel: FIRST_PRINCIPLES_MODEL,
    currentModelPolicyDigest: sha256Digest(canonicalStringify(FIRST_PRINCIPLES_MODEL_POLICY)),
    candidateOrdering: "highest_ranked_first",
    discoverySource: FIRST_PRINCIPLES_MODEL_POLICY.successorModelPolicy.discoverySource,
    candidates,
    probeResults,
    selectedCandidate: selected,
    healthDigest: health ? sha256Digest(canonicalStringify(health)) : null,
    authority: "model_policy_evidence_only_not_runtime_selection",
  };
  const modelProbeDigest = sha256Digest(canonicalStringify(evidence));
  state.lastScanAt = now.toISOString();
  state.lastProbeDigest = modelProbeDigest;
  state.lastCandidateModel = selected?.model || null;
  state.lastScanError = null;

  if (!selected) {
    return { evidence, modelProbeDigest, proposal: null };
  }

  const proposal = buildModelPolicyUpgradeProposal({
    selected,
    evidence,
    modelProbeDigest,
    now,
  });
  return {
    evidence,
    modelProbeDigest,
    proposal,
  };
}

export function ensureModelPolicySupervisorState(current) {
  if (!current.modelPolicySupervisor) {
    current.modelPolicySupervisor = {
      schema: "femled.tee.model_policy.supervisor_state.v1",
      lastScanAt: null,
      lastEvaluationAt: null,
      lastScanStartedAt: null,
      lastProbeDigest: null,
      lastCandidateModel: null,
      lastProposalDigest: null,
      lastScanError: null,
    };
  }
  current.modelPolicySupervisor.lastEvaluationAt ??= null;
  current.modelPolicySupervisor.lastScanStartedAt ??= null;
  current.modelPolicySupervisor.lastScanError ??= null;
  return current.modelPolicySupervisor;
}

function shouldScan(state, { now, scanIntervalMs }) {
  if (!Number.isFinite(scanIntervalMs) || scanIntervalMs < 0) return false;
  if (!state.lastScanAt) return true;
  const lastScan = Date.parse(state.lastScanAt);
  if (!Number.isFinite(lastScan)) return true;
  return now.getTime() - lastScan >= scanIntervalMs;
}

function strongerSuccessorCandidates(catalogCandidates = []) {
  const currentRank = rankModelName(FIRST_PRINCIPLES_MODEL);
  return (Array.isArray(catalogCandidates) ? catalogCandidates : [])
    .filter((candidate) => candidate.rank > currentRank)
    .sort((a, b) => b.rank - a.rank || String(a.model).localeCompare(String(b.model)))
    .map((candidate) => ({
      model: candidate.model,
      rank: candidate.rank,
      releaseChannel: candidate.releaseChannel,
      launchStage: candidate.launchStage || null,
      catalogDigest: candidate.catalogDigest || null,
      minimumCapabilities: candidate.minimumCapabilities || [],
      rationale: candidate.rationale || "",
    }));
}

function normalizeProbeResult(result, candidate) {
  return {
    schema: "femled.tee.model_policy.probe_result.v1",
    model: candidate.model,
    rank: candidate.rank,
    status: result?.status === "passed" ? "passed" : result?.status === "rejected" ? "rejected" : "failed",
    responseDigest: result?.responseDigest || null,
    reason: result?.reason || null,
    releaseChannel: candidate.releaseChannel,
    launchStage: candidate.launchStage || null,
    catalogDigest: candidate.catalogDigest || null,
  };
}

function withTimeout(promise, timeoutMs, message) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return promise;
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      const error = new Error(message);
      error.code = "ETIMEDOUT";
      reject(error);
    }, timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

function buildPublicScanError({ stage, error, now }) {
  const message = String(error?.message || error || "unknown");
  return {
    schema: "femled.tee.model_policy.scan_error.v1",
    stage,
    name: error?.name || "Error",
    code: error?.code || null,
    messageDigest: sha256Digest(message),
    recordedAt: now.toISOString(),
  };
}

function publicProbeFailureReason(error) {
  const code = error?.code ? ` ${error.code}` : "";
  return `${error?.name || "Error"}${code}`;
}

function buildModelPolicyUpgradeProposal({ selected, evidence, modelProbeDigest, now }) {
  const modelPolicyDiffDigest = sha256Digest(canonicalStringify({
    schema: "femled.tee.model_policy.diff_intent.v1",
    currentModel: evidence.currentModel,
    targetModel: selected.model,
    targetRank: selected.rank,
    requiredSourcePaths: MODEL_POLICY_UPGRADE_REQUIRED_SOURCE_PATHS,
  }));
  return {
    type: "model_policy_upgrade",
    problemStatement: `A stronger image-baked Gemini successor candidate ${selected.model} passed the golden probe; build a successor image that bakes this model through normal activation.`,
    requestedChange: {
      schema: MODEL_POLICY_UPGRADE_REQUEST_SCHEMA,
      surface: "model-policy",
      risk: "warning",
      generatedAt: now.toISOString(),
      currentModel: evidence.currentModel,
      targetModel: selected.model,
      targetRank: selected.rank,
      modelProbeDigest,
      modelPolicyDiffDigest,
      requiredSourcePaths: MODEL_POLICY_UPGRADE_REQUIRED_SOURCE_PATHS,
      authority: "repair_candidate_evidence_only_not_activation",
      instructions: [
        "Change only the image-baked model policy source and repair worker default model needed to promote the target model.",
        "Update src/first-principles-review.js and repair-worker/repair-worker-run.py together.",
        "Do not add runtime model selection, environment model overrides, model-list authority, deployment authority, or activation authority.",
        "Produce source, build, test, model-probe, and verification evidence for predecessor review.",
      ],
    },
    expectedCandidateEvidence: {
      selfHealingProposalDigest: true,
      modelProbeDigest: true,
      modelPolicyDiffDigest: true,
      sourceBundleDigest: true,
      candidateImageDigest: true,
      buildSummaryDigest: true,
      testSummaryDigest: true,
    },
  };
}

function rankModelName(model) {
  const text = String(model || "").toLowerCase();
  const version = /gemini-([0-9]+)(?:[.-]([0-9]+))?/.exec(text);
  const major = Number.parseInt(version?.[1] || "0", 10);
  const minor = Number.parseInt(version?.[2] || "0", 10);
  const proWeight = /pro/.test(text) ? 100 : 0;
  const previewPenalty = /preview|experimental|exp/.test(text) ? -5 : 0;
  return major * 1000 + minor * 10 + proWeight + previewPenalty;
}

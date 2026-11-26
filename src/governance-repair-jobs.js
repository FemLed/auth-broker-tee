import crypto from "node:crypto";
import { canonicalStringify, sha256Digest } from "./canonical-json.js";
import { recordRepairJobSummary } from "./governance-monitor.js";
import {
  buildRepairJobRequest,
  buildRepairJobStatus,
  buildRepairPromptEnvelope,
  EVIDENCE_INVESTIGATION_SCHEMA,
  validateRepairArtifactEnvelope,
  validateRepairCandidateSubmission,
} from "./governance-repair-contract.js";

const MAX_REPAIR_JOBS = 40;
const REPAIR_JOB_STALE_MS = 2 * 60 * 60 * 1000;
const TERMINAL_REPAIR_JOB_STATUSES = new Set(["finished", "candidate_submitted", "failed"]);
const COMPLETED_EPISODE_STATUSES = new Set(["finished", "candidate_submitted"]);

const repairJobs = [];

export function resetRepairJobsForTests() {
  repairJobs.length = 0;
}

export function repairJobDedupeKey(proposal = {}) {
  const payload = proposal?.payload || proposal || {};
  const type = String(payload.type || "operational_repair");
  const requestedChange = payload.requestedChange || {};
  if (type === "model_policy_upgrade") {
    const currentModel = String(requestedChange.currentModel || "");
    const targetModel = String(requestedChange.targetModel || "");
    if (currentModel || targetModel) {
      return `model_policy_upgrade:${currentModel}->${targetModel}`;
    }
  }
  const surface = String(requestedChange.surface || "default");
  return `repair:${type}:${surface}`;
}

export function hasEpisodeRepairJob(dedupeKey) {
  if (!dedupeKey) return false;
  return repairJobs.some((candidate) => {
    if (candidate.dedupeKey !== dedupeKey) return false;
    const status = candidate.status?.payload?.status;
    if (!TERMINAL_REPAIR_JOB_STATUSES.has(status)) return true;
    return COMPLETED_EPISODE_STATUSES.has(status) && !candidate.episodeCleared;
  });
}

export function clearResolvedRepairJobEpisodes(activeDedupeKeys = new Set()) {
  const active = activeDedupeKeys instanceof Set ? activeDedupeKeys : new Set(activeDedupeKeys || []);
  for (const job of repairJobs) {
    const status = job.status?.payload?.status;
    if (COMPLETED_EPISODE_STATUSES.has(status) && !job.episodeCleared && job.dedupeKey && !active.has(job.dedupeKey)) {
      job.episodeCleared = true;
    }
  }
}

export function createRepairJobForProposal({
  proposalEnvelope,
  healthSnapshot,
  requestedChange = null,
  now = new Date(),
} = {}) {
  if (findOpenJobByProposalDigest(proposalEnvelope.payloadDigest)) {
    return findOpenJobByProposalDigest(proposalEnvelope.payloadDigest);
  }
  const resolvedRequestedChange = requestedChange || proposalEnvelope.payload.requestedChange;
  const dedupeKey = repairJobDedupeKey({
    type: proposalEnvelope.payload.type,
    requestedChange: resolvedRequestedChange,
  });
  const promptEnvelope = buildRepairPromptEnvelope({
    proposalEnvelope,
    healthSnapshotDigest: sha256Digest(canonicalStringify(healthSnapshot)),
    requestedChange: resolvedRequestedChange,
  });
  const callbackToken = crypto.randomBytes(32).toString("hex");
  const callbackTokenHash = sha256Digest(callbackToken);
  const jobRequest = buildRepairJobRequest({
    proposalEnvelope,
    promptEnvelope,
    callbackTokenHash,
    requestedAt: now,
  });
  const status = buildRepairJobStatus({
    jobRequest,
    status: "requested",
    updatedAt: now,
  });
  const job = {
    schema: "femled.tee.repair_worker.job_record.v1",
    jobId: jobRequest.payload.jobId,
    proposalDigest: proposalEnvelope.payloadDigest,
    dedupeKey,
    episodeCleared: false,
    promptEnvelope,
    promptDigest: jobRequest.payload.promptDigest,
    jobRequest,
    status,
    artifact: null,
    investigationArtifacts: [],
    candidateSubmission: null,
    callbackToken,
    callbackTokenHash,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };
  repairJobs.push(job);
  while (repairJobs.length > MAX_REPAIR_JOBS) repairJobs.shift();
  return publicJob(job);
}

export function recordRepairArtifact(envelope, { callbackToken, now = new Date() } = {}) {
  if (envelope?.schema === EVIDENCE_INVESTIGATION_SCHEMA) {
    return recordInvestigationArtifact(envelope, { callbackToken, now });
  }
  const artifact = validateRepairArtifactEnvelope(envelope);
  const job = findOpenJobByProposalDigest(artifact.proposalDigest, { raw: true });
  if (!job) throw new Error("repair job not found for artifact proposal digest");
  assertCallbackToken(job, callbackToken);
  job.artifact = artifact;
  job.status = buildRepairJobStatus({
    jobRequest: job.jobRequest,
    status: "finished",
    artifactDigest: artifact.artifactDigest,
    summaryDigest: artifact.buildSummaryDigest || artifact.testSummaryDigest,
    updatedAt: now,
  });
  job.updatedAt = now.toISOString();
  return publicJob(job);
}

export function recordInvestigationArtifact(envelope, { callbackToken, now = new Date() } = {}) {
  const investigation = validateRepairArtifactEnvelope(envelope);
  const job = findOpenJobByProposalDigest(investigation.proposalDigest, { raw: true });
  if (!job) throw new Error("repair job not found for investigation proposal digest");
  assertCallbackToken(job, callbackToken);
  job.investigationArtifacts.push(investigation);
  job.status = buildRepairJobStatus({
    jobRequest: job.jobRequest,
    status: "investigation_recorded",
    artifactDigest: investigation.investigationDigest,
    summaryDigest: investigation.answerDigest,
    updatedAt: now,
  });
  job.updatedAt = now.toISOString();
  return publicJob(job);
}

export function recordRepairCandidateSubmission(submission, { callbackToken, now = new Date() } = {}) {
  const candidate = validateRepairCandidateSubmission(submission);
  const job = findOpenJobByProposalDigest(candidate.selfHealingProposalDigest, { raw: true });
  if (!job) throw new Error("repair job not found for candidate proposal digest");
  assertCallbackToken(job, callbackToken);
  job.candidateSubmission = candidate;
  job.status = buildRepairJobStatus({
    jobRequest: job.jobRequest,
    status: "candidate_submitted",
    artifactDigest: candidate.submissionDigest,
    summaryDigest: candidate.complianceSummaryDigest,
    updatedAt: now,
  });
  job.updatedAt = now.toISOString();
  return publicJob(job);
}

export function getPendingRepairJobsForLaunch() {
  return repairJobs
    .filter((job) => job.status.payload.status === "requested")
    .map((job) => ({
      jobId: job.jobId,
      proposalDigest: job.proposalDigest,
      promptEnvelope: job.promptEnvelope,
      promptDigest: job.promptDigest,
      callbackToken: job.callbackToken,
      callbackTokenHash: job.callbackTokenHash,
      jobRequestDigest: job.jobRequest.payloadDigest,
    }));
}

export function markRepairJobRunning(jobId, { now = new Date() } = {}) {
  const job = repairJobs.find((candidate) => candidate.jobId === jobId);
  if (!job) throw new Error("repair job not found");
  job.status = buildRepairJobStatus({
    jobRequest: job.jobRequest,
    status: "running",
    updatedAt: now,
  });
  job.updatedAt = now.toISOString();
  return publicJob(job);
}

export function getRepairJobManifest({ now = new Date() } = {}) {
  const openJobs = repairJobs.map(publicJob);
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  // Keep completed jobs in openJobs so summarizeSelfHealingEvidence can still
  // link artifactDigest/candidateSubmissionDigest, but count staleness only
  // over non-terminal jobs so finished jobs never self-trigger repair loops.
  const activeJobs = openJobs.filter((job) => !TERMINAL_REPAIR_JOB_STATUSES.has(job.status?.payload?.status));
  const ages = activeJobs.map((job) => Math.max(0, nowMs - Date.parse(job.createdAt)));
  const summary = {
    schema: "femled.tee.repair_worker.job_age_summary.v1",
    staleThresholdMs: REPAIR_JOB_STALE_MS,
    oldestOpenJobAgeMs: ages.length ? Math.max(...ages) : 0,
    staleOpenJobCount: ages.filter((age) => age >= REPAIR_JOB_STALE_MS).length,
  };
  recordRepairJobSummary(summary);
  return {
    schema: "femled.tee.repair_worker.jobs_manifest.v1",
    openJobDigests: openJobs.map((job) => job.jobRequestDigest),
    openJobs,
    summary,
  };
}

function findOpenJobByProposalDigest(proposalDigest, { raw = false } = {}) {
  const job = repairJobs.find((candidate) => candidate.proposalDigest === proposalDigest);
  if (!job) return null;
  return raw ? job : publicJob(job);
}

function publicJob(job) {
  return {
    schema: job.schema,
    jobId: job.jobId,
    proposalDigest: job.proposalDigest,
    promptDigest: job.promptDigest,
    jobRequestDigest: job.jobRequest.payloadDigest,
    jobRequest: job.jobRequest,
    statusDigest: job.status.payloadDigest,
    status: job.status,
    artifactDigest: job.artifact?.artifactDigest || null,
    investigationArtifactDigests: (job.investigationArtifacts || []).map((artifact) => artifact.investigationDigest),
    candidateSubmissionDigest: job.candidateSubmission?.submissionDigest || null,
    callbackTokenHash: job.callbackTokenHash,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
  };
}

function assertCallbackToken(job, callbackToken) {
  if (!callbackToken || sha256Digest(callbackToken) !== job.callbackTokenHash) {
    throw new Error("invalid repair job callback token");
  }
}

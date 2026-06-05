import { canonicalStringify, sha256Digest } from "./canonical-json.js";

const MAX_RECENT_EVENTS = 80;
const MAX_REASON_LENGTH = 500;
const CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5;
const CIRCUIT_BREAKER_OPEN_MS = 60_000;
const MAX_TENANT_CONTRACT_ROUTES = 20;
const SELF_IMPROVEMENT_FAILURE_THRESHOLD = 2;
const REPAIR_LAUNCH_FAILURE_THRESHOLD = 1;
const STALE_REPAIR_JOB_COUNT_THRESHOLD = 1;
const MANIFEST_ATTESTATION_FAILURE_THRESHOLD = 1;
const TOKEN_DEPOSIT_FAILURE_THRESHOLD = 3;
const TOKEN_DEPOSIT_HIGH_RATE_MIN_ATTEMPTS = 5;
const TOKEN_DEPOSIT_HIGH_FAILURE_RATE = 0.6;
const TENANT_ROUTE_LOOKUP_FAILURE_THRESHOLD = 3;
const ROUTE_PROOF_FAILURE_THRESHOLD = 1;
const DEPLOY_WEBHOOK_FAILURE_THRESHOLD = 2;

const counters = {
  vertexCalls: 0,
  vertexSuccesses: 0,
  vertexFailures: 0,
  vertexRetries: 0,
  vertexCircuitOpenDenials: 0,
  vertexParseFailures: 0,
  vertexRetryExhaustions: 0,
  modelProbeSuccesses: 0,
  modelProbeFailures: 0,
  attestationRefreshSuccesses: 0,
  attestationRefreshFailures: 0,
  wifSuccesses: 0,
  wifFailures: 0,
  routeBundleRefreshSuccesses: 0,
  routeBundleRefreshFailures: 0,
  routeGateDenials: 0,
  preapprovalIssued: 0,
  preapprovalRejected: 0,
  activationChallenges: 0,
  activationSuccesses: 0,
  activationFailures: 0,
  retirementEvents: 0,
  selfImprovementEvaluations: 0,
  selfImprovementFailures: 0,
  repairLaunchAttempts: 0,
  repairLaunchFailures: 0,
  manifestAttestationSuccesses: 0,
  manifestAttestationFailures: 0,
  tokenDepositFailures: 0,
  tenantRouteLookupFailures: 0,
  routeProofFailures: 0,
  deployWebhookFailures: 0,
};

const lastSuccessAt = {};
const lastFailureAt = {};
const recentEvents = [];
const tenantContractRoutes = new Map();
const operational = {
  selfImprovement: {
    schema: "femled.tee.self_improvement.health.v1",
    lastSelfImprovementAt: null,
    lastSelfImprovementStatus: null,
    lastSelfImprovementError: null,
  },
  repairLaunch: {
    schema: "femled.tee.repair_worker.launch_health.v1",
    lastRepairLaunchAttemptAt: null,
    lastRepairLaunchStatus: null,
    lastRepairLaunchError: null,
  },
  repairJobs: {
    schema: "femled.tee.repair_worker.job_health.v1",
    lastRepairJobSummaryAt: null,
    staleOpenJobCount: 0,
    oldestOpenJobAgeMs: 0,
    staleThresholdMs: null,
  },
  manifestAttestation: {
    schema: "femled.tee.manifest_attestation.health.v1",
    lastManifestAttestationAt: null,
    lastManifestAttestationStatus: null,
    lastManifestAttestationSurface: null,
    lastManifestAttestationError: null,
  },
};
let vertexConsecutiveFailures = 0;
let vertexCircuitOpenUntil = 0;
let lastHealthyAt = null;

export function resetGovernanceMonitorForTests() {
  for (const key of Object.keys(counters)) counters[key] = 0;
  for (const key of Object.keys(lastSuccessAt)) delete lastSuccessAt[key];
  for (const key of Object.keys(lastFailureAt)) delete lastFailureAt[key];
  recentEvents.length = 0;
  tenantContractRoutes.clear();
  resetOperationalState();
  vertexConsecutiveFailures = 0;
  vertexCircuitOpenUntil = 0;
  lastHealthyAt = null;
}

export function recordVertexCall({ status, durationMs = null, retries = 0, model = null, reason = "" } = {}) {
  counters.vertexCalls += 1;
  counters.vertexRetries += Number(retries || 0);
  if (status === "success") {
    counters.vertexSuccesses += 1;
    vertexConsecutiveFailures = 0;
    lastSuccessAt.vertex = nowIso();
  } else {
    counters.vertexFailures += 1;
    vertexConsecutiveFailures += 1;
    lastFailureAt.vertex = nowIso();
    if (vertexConsecutiveFailures >= CIRCUIT_BREAKER_FAILURE_THRESHOLD) {
      vertexCircuitOpenUntil = Date.now() + CIRCUIT_BREAKER_OPEN_MS;
    }
  }
  recordEvent("vertex_call", status, { durationMs, retries, model, reason });
}

export function recordVertexCircuitOpen({ model = null, reason = "" } = {}) {
  counters.vertexCircuitOpenDenials += 1;
  recordEvent("vertex_circuit_open", "denied", { model, reason });
}

export function recordVertexParseFailure({ reason = "" } = {}) {
  counters.vertexParseFailures += 1;
  lastFailureAt.vertexParse = nowIso();
  recordEvent("vertex_parse_failure", "failed", { reason });
}

export function recordVertexRetryExhausted({ reason = "" } = {}) {
  counters.vertexRetryExhaustions += 1;
  lastFailureAt.vertexRetryExhausted = nowIso();
  recordEvent("vertex_retry_exhausted", "failed", { reason });
}

export function recordModelProbe({ status, model, reason = "" } = {}) {
  if (status === "success") {
    counters.modelProbeSuccesses += 1;
    lastSuccessAt.modelProbe = nowIso();
  } else {
    counters.modelProbeFailures += 1;
    lastFailureAt.modelProbe = nowIso();
  }
  recordEvent("model_probe", status, { model, reason });
}

export function recordAttestationRefresh({ status, reason = "" } = {}) {
  if (status === "success") {
    counters.attestationRefreshSuccesses += 1;
    lastSuccessAt.attestationRefresh = nowIso();
  } else {
    counters.attestationRefreshFailures += 1;
    lastFailureAt.attestationRefresh = nowIso();
  }
  recordEvent("attestation_refresh", status, { reason });
}

export function recordWifTokenExchange({ status, reason = "" } = {}) {
  if (status === "success") {
    counters.wifSuccesses += 1;
    lastSuccessAt.wif = nowIso();
  } else {
    counters.wifFailures += 1;
    lastFailureAt.wif = nowIso();
  }
  recordEvent("wif_token_exchange", status, { reason });
}

export function recordRouteBundleRefresh({ status, reason = "" } = {}) {
  if (status === "success") {
    counters.routeBundleRefreshSuccesses += 1;
    lastSuccessAt.routeBundleRefresh = nowIso();
  } else {
    counters.routeBundleRefreshFailures += 1;
    lastFailureAt.routeBundleRefresh = nowIso();
  }
  recordEvent("route_bundle_refresh", status, { reason });
}

export function recordRouteGateDenied({ pathname = "" } = {}) {
  counters.routeGateDenials += 1;
  recordEvent("route_gate_denied", "denied", { pathDigest: sha256Digest(pathname) });
}

export function recordPreapproval({ status, reason = "", candidateDigest = "" } = {}) {
  if (status === "issued") {
    counters.preapprovalIssued += 1;
    lastSuccessAt.preapproval = nowIso();
  } else {
    counters.preapprovalRejected += 1;
    lastFailureAt.preapproval = nowIso();
  }
  recordEvent("preapproval", status, { reason, candidateDigest });
}

export function recordActivationChallenge({ candidateDigest = "" } = {}) {
  counters.activationChallenges += 1;
  recordEvent("activation_challenge", "issued", { candidateDigest });
}

export function recordActivation({ status, reason = "", candidateDigest = "" } = {}) {
  if (status === "success") {
    counters.activationSuccesses += 1;
    lastSuccessAt.activation = nowIso();
  } else {
    counters.activationFailures += 1;
    lastFailureAt.activation = nowIso();
  }
  recordEvent("activation", status, { reason, candidateDigest });
}

export function recordRetirement({ successorDigest = "" } = {}) {
  counters.retirementEvents += 1;
  recordEvent("retirement", "successor_activated", { successorDigest });
}

export function recordSelfImprovement({ status, error = null, proposalType = null } = {}) {
  counters.selfImprovementEvaluations += 1;
  operational.selfImprovement.lastSelfImprovementAt = nowIso();
  operational.selfImprovement.lastSelfImprovementStatus = normalizeStatus(status);
  if (status === "failed") {
    counters.selfImprovementFailures += 1;
    lastFailureAt.selfImprovement = operational.selfImprovement.lastSelfImprovementAt;
    operational.selfImprovement.lastSelfImprovementError = publicError(error);
  } else {
    counters.selfImprovementFailures = 0;
    lastSuccessAt.selfImprovement = operational.selfImprovement.lastSelfImprovementAt;
    operational.selfImprovement.lastSelfImprovementError = null;
  }
  recordEvent("self_improvement", status, {
    errorCategory: status === "failed" ? publicError(error).category : null,
    proposalType,
  });
}

export function recordRepairLaunch({ status, error = null, launchedCount = 0 } = {}) {
  counters.repairLaunchAttempts += 1;
  operational.repairLaunch.lastRepairLaunchAttemptAt = nowIso();
  operational.repairLaunch.lastRepairLaunchStatus = normalizeStatus(status);
  if (status === "failed") {
    counters.repairLaunchFailures += 1;
    lastFailureAt.repairLaunch = operational.repairLaunch.lastRepairLaunchAttemptAt;
    operational.repairLaunch.lastRepairLaunchError = publicError(error);
  } else {
    counters.repairLaunchFailures = 0;
    lastSuccessAt.repairLaunch = operational.repairLaunch.lastRepairLaunchAttemptAt;
    operational.repairLaunch.lastRepairLaunchError = null;
  }
  recordEvent("repair_launch", status, {
    errorCategory: status === "failed" ? publicError(error).category : null,
    launchedCount,
  });
}

export function recordRepairJobSummary({ staleOpenJobCount = 0, oldestOpenJobAgeMs = 0, staleThresholdMs = null } = {}) {
  operational.repairJobs.lastRepairJobSummaryAt = nowIso();
  operational.repairJobs.staleOpenJobCount = Number(staleOpenJobCount || 0);
  operational.repairJobs.oldestOpenJobAgeMs = Number(oldestOpenJobAgeMs || 0);
  operational.repairJobs.staleThresholdMs = staleThresholdMs;
  recordEvent("repair_job_summary", "success", {
    staleOpenJobCount: operational.repairJobs.staleOpenJobCount,
    oldestOpenJobAgeMs: operational.repairJobs.oldestOpenJobAgeMs,
  });
}

export function recordManifestAttestation({ surface, status, error = null } = {}) {
  if (status === "success") {
    counters.manifestAttestationSuccesses += 1;
    counters.manifestAttestationFailures = 0;
    lastSuccessAt.manifestAttestation = nowIso();
  } else {
    counters.manifestAttestationFailures += 1;
    lastFailureAt.manifestAttestation = nowIso();
  }
  const recordedAt = status === "success" ? lastSuccessAt.manifestAttestation : lastFailureAt.manifestAttestation;
  operational.manifestAttestation.lastManifestAttestationAt = recordedAt;
  operational.manifestAttestation.lastManifestAttestationStatus = normalizeStatus(status);
  operational.manifestAttestation.lastManifestAttestationSurface = sanitizeSurface(surface);
  operational.manifestAttestation.lastManifestAttestationError = status === "success" ? null : publicError(error);
  recordEvent("manifest_attestation", status, {
    surface: sanitizeSurface(surface),
    errorCategory: status === "failed" ? publicError(error).category : null,
  });
}

export function recordTokenDeposit({ routeDigest, status, httpStatus = null, error = null } = {}) {
  const route = routeMetric(routeDigest);
  if (status === "success") {
    counters.tokenDepositFailures = 0;
    route.tokenDepositSuccesses += 1;
    route.tokenDepositFailures = 0;
    route.lastTokenDepositError = null;
    lastSuccessAt.tokenDeposit = nowIso();
  } else {
    counters.tokenDepositFailures += 1;
    route.tokenDepositFailures += 1;
    route.lastTokenDepositFailureAt = nowIso();
    route.lastTokenDepositError = publicHttpError({ httpStatus, error });
    lastFailureAt.tokenDeposit = route.lastTokenDepositFailureAt;
  }
  route.tokenDepositFailureRate = computeFailureRate(route.tokenDepositFailures, route.tokenDepositSuccesses);
  recordEvent("token_deposit", status, {
    routeDigest,
    httpStatusClass: httpStatusClass(httpStatus),
    errorCategory: status === "success" ? null : publicHttpError({ httpStatus, error }).category,
  });
}

export function recordTenantRouteLookup({ status, routeDigest = null, lookupDigest = null } = {}) {
  const route = routeMetric(routeDigest || lookupDigest || "sha256:unknown");
  if (status === "success") {
    counters.tenantRouteLookupFailures = 0;
    route.tenantRouteLookupFailures = 0;
    route.lastTenantRouteLookupError = null;
    lastSuccessAt.tenantRouteLookup = nowIso();
    recordEvent("tenant_route_lookup", "success", {
      routeDigest: routeDigest || null,
      lookupDigest: routeDigest ? null : lookupDigest,
    });
    return;
  }
  counters.tenantRouteLookupFailures += 1;
  route.tenantRouteLookupFailures += 1;
  route.lastTenantRouteLookupFailureAt = nowIso();
  route.lastTenantRouteLookupError = { category: "missing_route" };
  lastFailureAt.tenantRouteLookup = route.lastTenantRouteLookupFailureAt;
  recordEvent("tenant_route_lookup", "failed", {
    routeDigest: routeDigest || null,
    lookupDigest: routeDigest ? null : lookupDigest,
    errorCategory: "missing_route",
  });
}

export function recordRouteProof({ routeDigest, status, error = null } = {}) {
  const route = routeMetric(routeDigest);
  if (status === "success") {
    counters.routeProofFailures = 0;
    route.routeProofFailures = 0;
    route.lastRouteProofError = null;
    lastSuccessAt.routeProof = nowIso();
    recordEvent("route_proof", "success", { routeDigest });
    return;
  }
  counters.routeProofFailures += 1;
  route.routeProofFailures += 1;
  route.lastRouteProofFailureAt = nowIso();
  route.lastRouteProofError = { category: "route_proof_failed", errorCategory: publicError(error).category };
  lastFailureAt.routeProof = route.lastRouteProofFailureAt;
  recordEvent("route_proof", "failed", {
    routeDigest,
    errorCategory: "route_proof_failed",
  });
}

export function recordDeployWebhook({ routeDigest = null, repoDigest = null, status, httpStatus = null, error = null } = {}) {
  const route = routeMetric(routeDigest || repoDigest || "sha256:unknown");
  if (status === "success") {
    counters.deployWebhookFailures = 0;
    route.deployWebhookFailures = 0;
    route.lastDeployWebhookError = null;
    lastSuccessAt.deployWebhook = nowIso();
    recordEvent("deploy_webhook", "success", {
      routeDigest,
      repoDigest: routeDigest ? null : repoDigest,
      httpStatusClass: httpStatusClass(httpStatus),
    });
    return;
  }
  counters.deployWebhookFailures += 1;
  route.deployWebhookFailures += 1;
  route.lastDeployWebhookFailureAt = nowIso();
  route.lastDeployWebhookError = publicHttpError({ httpStatus, error });
  lastFailureAt.deployWebhook = route.lastDeployWebhookFailureAt;
  recordEvent("deploy_webhook", "failed", {
    routeDigest,
    repoDigest: routeDigest ? null : repoDigest,
    httpStatusClass: httpStatusClass(httpStatus),
    errorCategory: route.lastDeployWebhookError.category,
  });
}

export function genericErrorCategory(error) {
  return publicError(error).category;
}

export function isVertexCircuitOpen() {
  return Date.now() < vertexCircuitOpenUntil;
}

export function getVertexCircuitState() {
  return {
    open: isVertexCircuitOpen(),
    openUntil: vertexCircuitOpenUntil ? new Date(vertexCircuitOpenUntil).toISOString() : null,
    consecutiveFailures: vertexConsecutiveFailures,
    failureThreshold: CIRCUIT_BREAKER_FAILURE_THRESHOLD,
  };
}

export function buildHealthSnapshot({ governanceStatus = "unknown", epoch = 0, lineageDigest = null } = {}) {
  const recent = recentEvents.slice();
  const unresolvedFailures = computeUnresolvedFailures();
  const availabilityRisk = computeAvailabilityRisk();
  const governanceRisk = computeGovernanceRisk(governanceStatus);
  const status = availabilityRisk === "critical" || governanceRisk === "critical"
    ? "critical"
    : availabilityRisk === "warning" || governanceRisk === "warning"
      ? "degraded"
      : "healthy";
  if (status === "healthy") lastHealthyAt = nowIso();
  return {
    schema: "femled.tee.governance.health.v1",
    status,
    availabilityRisk,
    governanceRisk,
    governanceStatus,
    epoch,
    lineageDigest,
    counters: { ...counters },
    lastSuccessAt: { ...lastSuccessAt },
    lastFailureAt: { ...lastFailureAt },
    lastHealthyAt,
    unresolvedFailures,
    vertexCircuit: getVertexCircuitState(),
    operational: buildOperationalSummary(),
    recentEventsDigest: sha256Digest(canonicalStringify(recent)),
    recentEventCount: recent.length,
    generatedAt: nowIso(),
  };
}

function computeAvailabilityRisk() {
  const unresolved = computeUnresolvedFailures();
  if (isVertexCircuitOpen() || unresolved.vertexRetryExhausted || unresolved.attestationRefreshFailures >= 3) {
    return "critical";
  }
  if (
    unresolved.vertex ||
    unresolved.wif ||
    unresolved.routeBundleRefresh ||
    unresolved.modelProbe ||
    unresolved.selfImprovement ||
    unresolved.repairLaunch ||
    unresolved.staleRepairJobs ||
    unresolved.manifestAttestation ||
    unresolved.tokenDeposit ||
    unresolved.tenantRouteLookup ||
    unresolved.routeProof ||
    unresolved.deployWebhook
  ) {
    return "warning";
  }
  return "low";
}

function computeGovernanceRisk(governanceStatus) {
  if (governanceStatus !== "active") return "critical";
  const unresolved = computeUnresolvedFailures();
  if (unresolved.activation || unresolved.preapproval) return "warning";
  return "low";
}

function computeUnresolvedFailures() {
  const operationalUnresolved = computeOperationalUnresolved();
  return {
    vertex: failureAfterSuccess("vertex"),
    vertexRetryExhausted: failureAfterSuccess("vertexRetryExhausted", "vertex"),
    vertexParse: failureAfterSuccess("vertexParse", "vertex"),
    modelProbe: failureAfterSuccess("modelProbe"),
    attestationRefresh: failureAfterSuccess("attestationRefresh"),
    attestationRefreshFailures: unresolvedFailureCount("attestation_refresh", "attestationRefresh"),
    wif: failureAfterSuccess("wif"),
    routeBundleRefresh: failureAfterSuccess("routeBundleRefresh"),
    preapproval: failureAfterSuccess("preapproval"),
    activation: failureAfterSuccess("activation"),
    ...operationalUnresolved.flags,
  };
}

function failureAfterSuccess(failureKey, successKey = failureKey) {
  const failureAt = Date.parse(lastFailureAt[failureKey] || "");
  if (!Number.isFinite(failureAt)) return false;
  const successAt = Date.parse(lastSuccessAt[successKey] || "");
  return !Number.isFinite(successAt) || failureAt > successAt;
}

function unresolvedFailureCount(eventKind, successKey) {
  const successAt = Date.parse(lastSuccessAt[successKey] || "");
  return recentEvents.filter((event) =>
    event.kind === eventKind &&
    event.status !== "success" &&
    (!Number.isFinite(successAt) || Date.parse(event.at) > successAt)
  ).length;
}

function buildOperationalSummary() {
  const unresolved = computeOperationalUnresolved();
  return {
    schema: "femled.tee.privacy_safe_operational_health.v1",
    selfImprovement: { ...operational.selfImprovement },
    repairLaunch: { ...operational.repairLaunch },
    repairJobs: { ...operational.repairJobs },
    manifestAttestation: { ...operational.manifestAttestation },
    unresolved: unresolved.evidence,
    thresholds: {
      schema: "femled.tee.privacy_safe_operational_thresholds.v1",
      selfImprovementFailureThreshold: SELF_IMPROVEMENT_FAILURE_THRESHOLD,
      repairLaunchFailureThreshold: REPAIR_LAUNCH_FAILURE_THRESHOLD,
      staleRepairJobCountThreshold: STALE_REPAIR_JOB_COUNT_THRESHOLD,
      manifestAttestationFailureThreshold: MANIFEST_ATTESTATION_FAILURE_THRESHOLD,
      tokenDepositFailureThreshold: TOKEN_DEPOSIT_FAILURE_THRESHOLD,
      tokenDepositHighRateMinAttempts: TOKEN_DEPOSIT_HIGH_RATE_MIN_ATTEMPTS,
      tokenDepositHighFailureRate: TOKEN_DEPOSIT_HIGH_FAILURE_RATE,
      tenantRouteLookupFailureThreshold: TENANT_ROUTE_LOOKUP_FAILURE_THRESHOLD,
      routeProofFailureThreshold: ROUTE_PROOF_FAILURE_THRESHOLD,
      deployWebhookFailureThreshold: DEPLOY_WEBHOOK_FAILURE_THRESHOLD,
    },
    tenantContract: {
      schema: "femled.tee.tenant_contract.health.v1",
      tokenDepositFailures: counters.tokenDepositFailures,
      tenantRouteLookupFailures: counters.tenantRouteLookupFailures,
      routeProofFailures: counters.routeProofFailures,
      deployWebhookFailures: counters.deployWebhookFailures,
      routes: Array.from(tenantContractRoutes.values()).slice(-MAX_TENANT_CONTRACT_ROUTES),
    },
  };
}

function computeOperationalUnresolved() {
  const flags = {
    selfImprovement: counters.selfImprovementFailures >= SELF_IMPROVEMENT_FAILURE_THRESHOLD,
    repairLaunch: counters.repairLaunchFailures >= REPAIR_LAUNCH_FAILURE_THRESHOLD,
    staleRepairJobs: operational.repairJobs.staleOpenJobCount >= STALE_REPAIR_JOB_COUNT_THRESHOLD,
    manifestAttestation: counters.manifestAttestationFailures >= MANIFEST_ATTESTATION_FAILURE_THRESHOLD,
    tokenDeposit: false,
    tenantRouteLookup: false,
    routeProof: false,
    deployWebhook: false,
  };
  const evidence = {
    schema: "femled.tee.privacy_safe_operational_unresolved.v1",
    selfImprovement: flags.selfImprovement ? {
      failures: counters.selfImprovementFailures,
      threshold: SELF_IMPROVEMENT_FAILURE_THRESHOLD,
      lastError: operational.selfImprovement.lastSelfImprovementError,
    } : null,
    repairLaunch: flags.repairLaunch ? {
      failures: counters.repairLaunchFailures,
      threshold: REPAIR_LAUNCH_FAILURE_THRESHOLD,
      lastError: operational.repairLaunch.lastRepairLaunchError,
    } : null,
    staleRepairJobs: flags.staleRepairJobs ? {
      staleOpenJobCount: operational.repairJobs.staleOpenJobCount,
      threshold: STALE_REPAIR_JOB_COUNT_THRESHOLD,
      oldestOpenJobAgeMs: operational.repairJobs.oldestOpenJobAgeMs,
    } : null,
    manifestAttestation: flags.manifestAttestation ? {
      failures: counters.manifestAttestationFailures,
      threshold: MANIFEST_ATTESTATION_FAILURE_THRESHOLD,
      surface: operational.manifestAttestation.lastManifestAttestationSurface,
      lastError: operational.manifestAttestation.lastManifestAttestationError,
    } : null,
    tenantContract: {
      tokenDeposit: [],
      tenantRouteLookup: [],
      routeProof: [],
      deployWebhook: [],
    },
  };

  for (const route of tenantContractRoutes.values()) {
    const tokenAttempts = route.tokenDepositFailures + route.tokenDepositSuccesses;
    if (
      route.tokenDepositFailures >= TOKEN_DEPOSIT_FAILURE_THRESHOLD ||
      (tokenAttempts >= TOKEN_DEPOSIT_HIGH_RATE_MIN_ATTEMPTS && route.tokenDepositFailureRate >= TOKEN_DEPOSIT_HIGH_FAILURE_RATE)
    ) {
      flags.tokenDeposit = true;
      evidence.tenantContract.tokenDeposit.push({
        routeDigest: route.routeDigest,
        failures: route.tokenDepositFailures,
        attempts: tokenAttempts,
        failureRate: route.tokenDepositFailureRate,
      });
    }
    if (route.tenantRouteLookupFailures >= TENANT_ROUTE_LOOKUP_FAILURE_THRESHOLD) {
      flags.tenantRouteLookup = true;
      evidence.tenantContract.tenantRouteLookup.push({
        routeDigest: route.routeDigest,
        failures: route.tenantRouteLookupFailures,
      });
    }
    if (route.routeProofFailures >= ROUTE_PROOF_FAILURE_THRESHOLD) {
      flags.routeProof = true;
      evidence.tenantContract.routeProof.push({
        routeDigest: route.routeDigest,
        failures: route.routeProofFailures,
      });
    }
    if (route.deployWebhookFailures >= DEPLOY_WEBHOOK_FAILURE_THRESHOLD) {
      flags.deployWebhook = true;
      evidence.tenantContract.deployWebhook.push({
        routeDigest: route.routeDigest,
        failures: route.deployWebhookFailures,
      });
    }
  }
  evidence.tenantContract.tokenDeposit = evidence.tenantContract.tokenDeposit.slice(-MAX_TENANT_CONTRACT_ROUTES);
  evidence.tenantContract.tenantRouteLookup = evidence.tenantContract.tenantRouteLookup.slice(-MAX_TENANT_CONTRACT_ROUTES);
  evidence.tenantContract.routeProof = evidence.tenantContract.routeProof.slice(-MAX_TENANT_CONTRACT_ROUTES);
  evidence.tenantContract.deployWebhook = evidence.tenantContract.deployWebhook.slice(-MAX_TENANT_CONTRACT_ROUTES);
  return { flags, evidence };
}

function recordEvent(kind, status, fields = {}) {
  const event = {
    schema: "femled.tee.governance.monitor_event.v1",
    kind,
    status: String(status || "unknown").slice(0, 80),
    at: nowIso(),
    ...sanitizeFields(fields),
  };
  recentEvents.push(event);
  while (recentEvents.length > MAX_RECENT_EVENTS) recentEvents.shift();
}

function sanitizeFields(fields) {
  const out = {};
  for (const [key, value] of Object.entries(fields || {})) {
    if (value === null || value === undefined || value === "") continue;
    if (/token|secret|key|authorization|password/i.test(key)) {
      out[`${key}Digest`] = sha256Digest(String(value));
    } else if (/Digest$/.test(key)) {
      out[key] = isSha256Digest(value) ? value : sha256Digest(String(value));
    } else if (key === "errorCategory" || key === "httpStatusClass" || key === "surface") {
      out[key] = String(value).slice(0, 80);
    } else if (key === "reason") {
      out.reason = String(value).slice(0, MAX_REASON_LENGTH);
    } else if (typeof value === "string") {
      out[key] = value.slice(0, MAX_REASON_LENGTH);
    } else if (typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
    } else {
      out[`${key}Digest`] = sha256Digest(canonicalStringify(value));
    }
  }
  return out;
}

function nowIso() {
  return new Date().toISOString();
}

function routeMetric(routeDigest) {
  const digest = isSha256Digest(routeDigest) ? routeDigest : sha256Digest(String(routeDigest || "unknown"));
  if (!tenantContractRoutes.has(digest)) {
    tenantContractRoutes.set(digest, {
      schema: "femled.tee.tenant_contract.route_health.v1",
      routeDigest: digest,
      tokenDepositSuccesses: 0,
      tokenDepositFailures: 0,
      tokenDepositFailureRate: 0,
      tenantRouteLookupFailures: 0,
      routeProofFailures: 0,
      deployWebhookFailures: 0,
      lastTokenDepositFailureAt: null,
      lastTokenDepositError: null,
      lastTenantRouteLookupFailureAt: null,
      lastTenantRouteLookupError: null,
      lastRouteProofFailureAt: null,
      lastRouteProofError: null,
      lastDeployWebhookFailureAt: null,
      lastDeployWebhookError: null,
    });
  }
  return tenantContractRoutes.get(digest);
}

function publicHttpError({ httpStatus = null, error = null } = {}) {
  const status = Number(httpStatus);
  if (Number.isInteger(status)) {
    if (status >= 500) return { category: "http_5xx", httpStatusClass: "5xx" };
    if (status >= 400) return { category: "http_4xx", httpStatusClass: "4xx" };
    if (status >= 300) return { category: "http_3xx", httpStatusClass: "3xx" };
    return { category: "http_non_success", httpStatusClass: httpStatusClass(status) };
  }
  return publicError(error);
}

function computeFailureRate(failures, successes) {
  const total = failures + successes;
  return total > 0 ? failures / total : 0;
}

function publicError(error) {
  const code = String(error?.code || "");
  const name = String(error?.name || "");
  if (code === "ETIMEDOUT" || name === "TimeoutError") return { category: "timeout" };
  if (code === "ENOENT") return { category: "launcher_unavailable" };
  if (code === "MISSING_ROUTE") return { category: "missing_route" };
  if (code === "ROUTE_PROOF_FAILED") return { category: "route_proof_failed" };
  if (/AbortError/i.test(name)) return { category: "timeout" };
  if (/SyntaxError/i.test(name)) return { category: "parse_error" };
  if (/TypeError|FetchError/i.test(name)) return { category: "network_error" };
  return { category: "unknown" };
}

function httpStatusClass(status) {
  const numeric = Number(status);
  if (!Number.isInteger(numeric)) return null;
  return `${Math.floor(numeric / 100)}xx`;
}

function sanitizeSurface(surface) {
  return ["governance", "policy", "attestation"].includes(surface) ? surface : "unknown";
}

function normalizeStatus(status) {
  return status === "success" || status === "failed" || status === "skipped" ? status : "unknown";
}

function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/i.test(value);
}

function resetOperationalState() {
  operational.selfImprovement.lastSelfImprovementAt = null;
  operational.selfImprovement.lastSelfImprovementStatus = null;
  operational.selfImprovement.lastSelfImprovementError = null;
  operational.repairLaunch.lastRepairLaunchAttemptAt = null;
  operational.repairLaunch.lastRepairLaunchStatus = null;
  operational.repairLaunch.lastRepairLaunchError = null;
  operational.repairJobs.lastRepairJobSummaryAt = null;
  operational.repairJobs.staleOpenJobCount = 0;
  operational.repairJobs.oldestOpenJobAgeMs = 0;
  operational.repairJobs.staleThresholdMs = null;
  operational.manifestAttestation.lastManifestAttestationAt = null;
  operational.manifestAttestation.lastManifestAttestationStatus = null;
  operational.manifestAttestation.lastManifestAttestationSurface = null;
  operational.manifestAttestation.lastManifestAttestationError = null;
}

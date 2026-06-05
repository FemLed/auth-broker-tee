#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { canonicalStringify, sha256Digest } from "../src/canonical-json.js";
import {
  DEFAULT_MODEL_POLICY_SCAN_INTERVAL_MS,
  evaluateModelPolicyUpgradeOpportunity,
} from "../src/governance-model-policy-supervisor.js";
import {
  FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
  FIRST_PRINCIPLES_MODEL,
  FIRST_PRINCIPLES_MODEL_POLICY,
  FIRST_PRINCIPLES_RESPONSE_MIME_TYPE,
  FIRST_PRINCIPLES_RESPONSE_SCHEMA,
  FIRST_PRINCIPLES_VERTEX_LOCATION,
  isPermittedSuccessorModelCandidate,
} from "../src/first-principles-review.js";
import {
  FIRST_PRINCIPLES_VERTEX_GOOGLE_SEARCH_TOOLS,
  listFirstPrinciplesModelCatalogCandidates,
  probeFirstPrinciplesModelCandidate,
  vertexPublisherModelCatalogUrl,
} from "../src/vertex-gemini.js";

const DEFAULT_TEE_URL = "https://oauth-tee.femled.ai";
const REPORT_SCHEMA = "femled.tee.model_policy.scan_diagnostic.v1";
const DEFAULT_MANIFEST_TIMEOUT_MS = 15_000;
const DEFAULT_CATALOG_TIMEOUT_MS = 15_000;
const DEFAULT_PROBE_TIMEOUT_MS = 60_000;

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log(usage());
    return;
  }

  const report = {
    schema: REPORT_SCHEMA,
    generatedAt: new Date().toISOString(),
    mode: options.mode,
    teeUrl: options.teeUrl,
    gates: {},
    liveSupervisor: null,
    healthSummary: null,
    replay: null,
    diagnosis: null,
  };

  try {
    const published = await fetchGovernanceManifest(options);
    const manifest = published.payload;
    report.manifestDigest = published.payloadDigest || null;
    report.liveSupervisor = manifest.selfHealing?.modelPolicySupervisor || null;
    report.healthSummary = summarizeHealth(manifest.health);
    report.gates = analyzeGates(manifest, options);

    const blockingDiagnosis = firstBlockingDiagnosis(report.gates);
    if (blockingDiagnosis) {
      report.diagnosis = blockingDiagnosis;
      console.log(JSON.stringify(report, null, 2));
      return;
    }

    report.replay = await replaySupervisorScan({
      manifest,
      attestationToken: published.attestationToken,
      options,
    });
    report.diagnosis = diagnoseReplay(report.replay);
    console.log(JSON.stringify(report, null, 2));
  } catch (error) {
    report.diagnosis = "diagnostic_failed";
    report.error = serializeError(error);
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = 1;
  }
}

function parseArgs(argv) {
  const options = {
    teeUrl: DEFAULT_TEE_URL,
    mode: "tee-wif",
    accessToken: "",
    accessTokenCommand: "",
    projectId: process.env.GCP_PROJECT_ID || "",
    location: FIRST_PRINCIPLES_VERTEX_LOCATION,
    manifestTimeoutMs: DEFAULT_MANIFEST_TIMEOUT_MS,
    catalogTimeoutMs: DEFAULT_CATALOG_TIMEOUT_MS,
    probeTimeoutMs: DEFAULT_PROBE_TIMEOUT_MS,
    scanIntervalMs: DEFAULT_MODEL_POLICY_SCAN_INTERVAL_MS,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`${arg} requires a value`);
      return argv[i];
    };
    if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--tee-url") options.teeUrl = stripTrailingSlash(next());
    else if (arg === "--mode") options.mode = next();
    else if (arg === "--access-token") options.accessToken = next();
    else if (arg === "--access-token-command") options.accessTokenCommand = next();
    else if (arg === "--project-id") options.projectId = next();
    else if (arg === "--location") options.location = next();
    else if (arg === "--manifest-timeout-ms") options.manifestTimeoutMs = numberArg(arg, next());
    else if (arg === "--catalog-timeout-ms") options.catalogTimeoutMs = numberArg(arg, next());
    else if (arg === "--probe-timeout-ms") options.probeTimeoutMs = numberArg(arg, next());
    else if (arg === "--scan-interval-ms") options.scanIntervalMs = numberArg(arg, next());
    else throw new Error(`unknown argument: ${arg}`);
  }

  if (!["tee-wif", "token"].includes(options.mode)) {
    throw new Error("--mode must be tee-wif or token");
  }
  return options;
}

async function fetchGovernanceManifest(options) {
  const url = `${options.teeUrl}/.well-known/femled-tee-governance.json`;
  const response = await fetch(url, { signal: AbortSignal.timeout(options.manifestTimeoutMs) });
  if (!response.ok) {
    throw new Error(`governance manifest fetch failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

async function replaySupervisorScan({ manifest, attestationToken, options }) {
  const events = [];
  const current = {
    status: manifest.status,
    modelPolicySupervisor: cloneJson(manifest.selfHealing?.modelPolicySupervisor || null),
  };
  const health = cloneJson(manifest.health || null);
  const auth = await buildAuthContext({ attestationToken, options });
  const discoverModelCandidates = async () => measureEvent(events, "catalog_discovery", {
    mode: options.mode,
    projectId: auth.projectId || null,
    location: options.location,
  }, async () => withTimeout(
    options.mode === "tee-wif"
      ? listFirstPrinciplesModelCatalogCandidates()
      : listModelCatalogCandidatesWithToken(auth),
    options.catalogTimeoutMs,
    "catalog_discovery"
  ), summarizeCatalogCandidates);
  const probeModelCandidate = async (model, context) => measureEvent(events, "model_probe", {
    mode: options.mode,
    model,
    currentModel: context?.currentModel || FIRST_PRINCIPLES_MODEL,
  }, async () => withTimeout(
    options.mode === "tee-wif"
      ? probeFirstPrinciplesModelCandidate(model)
      : probeModelCandidateWithToken(model, auth),
    options.probeTimeoutMs,
    `model_probe:${model}`
  ), summarizeProbeResult);

  const beforeState = cloneJson(current.modelPolicySupervisor);
  try {
    const opportunity = await evaluateModelPolicyUpgradeOpportunity({
      current,
      health,
      scanIntervalMs: options.scanIntervalMs,
      discoverModelCandidates,
      probeModelCandidate,
    });
    return {
      status: "completed",
      beforeState,
      afterState: current.modelPolicySupervisor,
      events,
      proposalType: opportunity?.proposal?.type || null,
      targetModel: opportunity?.proposal?.requestedChange?.targetModel || null,
      modelProbeDigest: opportunity?.modelProbeDigest || null,
      selectedCandidate: opportunity?.evidence?.selectedCandidate?.model || null,
      candidateCount: opportunity?.evidence?.candidates?.length ?? null,
      probeResultCount: opportunity?.evidence?.probeResults?.length ?? null,
    };
  } catch (error) {
    return {
      status: "failed",
      beforeState,
      afterState: current.modelPolicySupervisor,
      events,
      error: serializeError(error),
    };
  }
}

async function buildAuthContext({ attestationToken, options }) {
  if (options.mode === "tee-wif") return {};

  const token = options.accessToken || readAccessTokenFromCommand(options.accessTokenCommand);
  if (!token) {
    throw new Error("token mode requires --access-token or --access-token-command");
  }
  const projectId = options.projectId || projectIdFromAttestation(attestationToken);
  if (!projectId) {
    throw new Error("token mode requires --project-id when it cannot be derived from the manifest attestation");
  }
  return {
    accessToken: token,
    projectId,
    location: options.location,
  };
}

async function listModelCatalogCandidatesWithToken({ accessToken, projectId, location }) {
  const models = [];
  let pageToken = "";
  do {
    const url = vertexPublisherModelCatalogUrl({ location, pageToken });
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "x-goog-user-project": projectId,
      },
    });
    if (!response.ok) {
      throw new Error(`Vertex model catalog fetch failed (${response.status}): ${truncate(await response.text(), 1000)}`);
    }
    const body = await response.json();
    models.push(...(body.publisherModels || body.models || []));
    pageToken = body.nextPageToken || "";
  } while (pageToken);
  return models
    .map(normalizePublisherModel)
    .filter((model) => isPermittedSuccessorModelCandidate(model.model))
    .sort((a, b) => b.rank - a.rank || a.model.localeCompare(b.model));
}

async function probeModelCandidateWithToken(model, { accessToken, projectId, location }) {
  if (!isPermittedSuccessorModelCandidate(model)) {
    return {
      status: "rejected",
      model,
      reason: "model does not match image-baked successor model constraints",
    };
  }
  const url = `${vertexBaseUrl(location)}/v1/projects/${encodeURIComponent(projectId)}/locations/${encodeURIComponent(location)}/publishers/google/models/${encodeURIComponent(model)}:generateContent`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      contents: [{
        role: "user",
        parts: [{ text: FIRST_PRINCIPLES_MODEL_POLICY.goldenProbe.prompt }],
      }],
      generationConfig: {
        temperature: FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
        responseMimeType: FIRST_PRINCIPLES_RESPONSE_MIME_TYPE,
        responseSchema: FIRST_PRINCIPLES_RESPONSE_SCHEMA,
      },
      tools: FIRST_PRINCIPLES_VERTEX_GOOGLE_SEARCH_TOOLS,
    }),
  });
  if (!response.ok) {
    return {
      status: "failed",
      model,
      reason: `Vertex generateContent failed (${response.status}): ${truncate(await response.text(), 1000)}`,
    };
  }
  const body = await response.json();
  const text = extractGenerateContentText(body);
  return {
    status: "passed",
    model,
    responseDigest: sha256Digest(text),
  };
}

function analyzeGates(manifest, options) {
  const supervisor = manifest.selfHealing?.modelPolicySupervisor || {};
  const health = manifest.health || {};
  const healthTrigger = chooseTrigger(health);
  return {
    governanceStatus: manifest.status || null,
    active: manifest.status === "active",
    healthTrigger,
    liveLastScanAt: supervisor.lastScanAt || null,
    scanIntervalMs: options.scanIntervalMs,
    scanIntervalEnabled: Number.isFinite(options.scanIntervalMs) && options.scanIntervalMs >= 0,
    shouldScan: shouldScan(supervisor, {
      now: new Date(),
      scanIntervalMs: options.scanIntervalMs,
    }),
  };
}

function firstBlockingDiagnosis(gates) {
  if (!gates.active) return "inactive_governance";
  if (gates.healthTrigger) return "preempted_by_health_trigger";
  if (!gates.scanIntervalEnabled) return "scan_interval_disabled";
  if (!gates.shouldScan) return "scan_not_due";
  return null;
}

function diagnoseReplay(replay) {
  if (replay.status !== "failed") {
    if (replay.proposalType === "model_policy_upgrade") return "scan_would_propose_model_policy_upgrade";
    if (replay.afterState?.lastScanAt) return "scan_completed_no_successor";
    return "scan_completed_without_state_update";
  }
  const failedEvent = [...replay.events].reverse().find((event) => event.status === "failed");
  if (failedEvent?.error?.code === "ETIMEDOUT" && failedEvent.stage === "catalog_discovery") {
    return "catalog_discovery_timed_out";
  }
  if (failedEvent?.stage === "catalog_discovery") {
    return "catalog_discovery_failed_before_state_update";
  }
  if (failedEvent?.error?.code === "ETIMEDOUT" && failedEvent.stage === "model_probe") {
    return "probe_hung_or_timed_out";
  }
  if (failedEvent?.stage === "model_probe") {
    return "probe_failed_before_state_update";
  }
  return "supervisor_replay_failed_before_state_update";
}

async function measureEvent(events, stage, input, fn, summarize) {
  const event = {
    stage,
    status: "running",
    input,
    startedAt: new Date().toISOString(),
  };
  events.push(event);
  const started = Date.now();
  try {
    const result = await fn();
    event.status = "completed";
    event.durationMs = Date.now() - started;
    event.summary = summarize ? summarize(result) : null;
    return result;
  } catch (error) {
    event.status = "failed";
    event.durationMs = Date.now() - started;
    event.error = serializeError(error);
    throw error;
  }
}

function withTimeout(promise, timeoutMs, label) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return promise;
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      const error = new Error(`${label} timed out after ${timeoutMs}ms`);
      error.code = "ETIMEDOUT";
      reject(error);
    }, timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

function shouldScan(state, { now, scanIntervalMs }) {
  if (!Number.isFinite(scanIntervalMs) || scanIntervalMs < 0) return false;
  if (!state.lastScanAt) return true;
  const lastScan = Date.parse(state.lastScanAt);
  if (!Number.isFinite(lastScan)) return true;
  return now.getTime() - lastScan >= scanIntervalMs;
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
  return null;
}

function summarizeHealth(health = {}) {
  return {
    status: health.status || null,
    availabilityRisk: health.availabilityRisk || null,
    governanceRisk: health.governanceRisk || null,
    counters: health.counters || {},
    unresolvedFailures: health.unresolvedFailures || {},
    vertexCircuit: health.vertexCircuit || null,
    generatedAt: health.generatedAt || null,
  };
}

function summarizeCatalogCandidates(candidates) {
  const list = Array.isArray(candidates) ? candidates : [];
  return {
    count: list.length,
    topModels: list.slice(0, 10).map((candidate) => ({
      model: candidate.model,
      rank: candidate.rank,
      launchStage: candidate.launchStage || null,
      releaseChannel: candidate.releaseChannel || null,
    })),
  };
}

function summarizeProbeResult(result) {
  return {
    model: result?.model || null,
    status: result?.status || null,
    responseDigest: result?.responseDigest || null,
    reason: result?.reason ? truncate(result.reason, 500) : null,
  };
}

function normalizePublisherModel(model = {}) {
  const rawName = model.name || model.publisherModel || model.model || "";
  const id = String(rawName).split("/").pop();
  return {
    schema: "femled.tee.model_policy.catalog_candidate.v1",
    model: id,
    publisher: "google",
    displayName: model.displayName || model.versionId || id,
    versionId: model.versionId || null,
    launchStage: model.launchStage || model.state || null,
    supportedActions: model.supportedActions || [],
    rank: rankModelName(id),
    catalogDigest: sha256Digest(canonicalStringify(model)),
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

function readAccessTokenFromCommand(command) {
  if (!command) return "";
  const result = spawnSync(command, {
    shell: true,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(`access token command failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return result.stdout.trim();
}

function projectIdFromAttestation(token) {
  if (!token) return "";
  try {
    const payload = JSON.parse(Buffer.from(String(token).split(".")[1], "base64url").toString("utf8"));
    return payload.submods?.container?.env?.GCP_PROJECT_ID ||
      payload.submods?.container?.env_override?.GCP_PROJECT_ID ||
      payload.submods?.gce?.project_id ||
      "";
  } catch {
    return "";
  }
}

function extractGenerateContentText(body) {
  const parts = body?.candidates?.[0]?.content?.parts || [];
  const text = parts.map((part) => part.text || "").join("").trim();
  if (!text) throw new Error("Vertex generateContent response did not include text");
  return text;
}

function vertexBaseUrl(location) {
  return location === "global"
    ? "https://aiplatform.googleapis.com"
    : `https://${location}-aiplatform.googleapis.com`;
}

function serializeError(error) {
  return {
    name: error?.name || "Error",
    message: error?.message || String(error),
    code: error?.code || null,
  };
}

function cloneJson(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function truncate(value, max) {
  const text = String(value || "");
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function numberArg(name, value) {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(`${name} must be a finite number`);
  return number;
}

function stripTrailingSlash(value) {
  return String(value).replace(/\/+$/, "");
}

function usage() {
  return `Usage: node scripts/diagnose-model-policy-scan.mjs [options]

Options:
  --tee-url <url>                 Auth broker TEE base URL. Default: ${DEFAULT_TEE_URL}
  --mode <tee-wif|token>          tee-wif uses production WIF helpers; token uses an explicit access token. Default: tee-wif
  --access-token <token>          OAuth access token for --mode token.
  --access-token-command <cmd>    Command that prints an OAuth access token for --mode token.
  --project-id <id>               GCP project for --mode token. Defaults to env or manifest attestation claims.
  --location <location>           Vertex AI location. Default: ${FIRST_PRINCIPLES_VERTEX_LOCATION}
  --manifest-timeout-ms <ms>      Live manifest fetch timeout. Default: ${DEFAULT_MANIFEST_TIMEOUT_MS}
  --catalog-timeout-ms <ms>       Model catalog discovery timeout. Default: ${DEFAULT_CATALOG_TIMEOUT_MS}
  --probe-timeout-ms <ms>         Candidate golden-probe timeout. Default: ${DEFAULT_PROBE_TIMEOUT_MS}
  --scan-interval-ms <ms>         Scan interval gate to replay. Default: ${DEFAULT_MODEL_POLICY_SCAN_INTERVAL_MS}
  --help, -h                      Show this help.

Examples:
  node scripts/diagnose-model-policy-scan.mjs --mode tee-wif
  node scripts/diagnose-model-policy-scan.mjs --mode token --access-token-command "gcloud auth print-access-token"
`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

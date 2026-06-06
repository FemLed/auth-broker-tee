import {
  canonicalStringify,
  sha256Digest,
} from "./canonical-json.js";
import { getAttestedImageDigest, getLauncherAttestationClaims } from "./gcp-auth.js";
import { jsonResponse, textResponse } from "./http-helpers.js";
import { requestAttestationToken } from "./attestation.js";
import { verifyGitHubActionsOidc } from "./github-oidc.js";
import {
  buildFirstPrinciplesPrompt,
  FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
  FIRST_PRINCIPLES_MODEL,
  FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
  FIRST_PRINCIPLES_POLICY_VERSION,
  FIRST_PRINCIPLES_PROMPT_DIGEST,
  FIRST_PRINCIPLES_RESPONSE_MIME_TYPE,
  FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST,
  FIRST_PRINCIPLES_VERTEX_LOCATION,
  parseFirstPrinciplesDecision,
} from "./first-principles-review.js";
import { generateFirstPrinciplesContent } from "./vertex-gemini.js";
import { getRouteRegistryStatus } from "./route-registry.js";
import { buildGovernanceManifestPayload } from "./governance-state.js";
import { recordManifestAttestation } from "./governance-monitor.js";

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_DIFF_BYTES = 850 * 1024;
const MAX_CHANGED_FILES = 300;
const ADJUDICATION_SCHEMA = "femled.first_principles.adjudication.v1";
const POLICY_SCHEMA = "femled.tee.policy.v1";
const FIRST_PRINCIPLES_WORKFLOW_IDENTITY =
  "FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master";

export async function handleFirstPrinciplesAdjudicate(req, res) {
  if (req.method !== "POST") {
    return textResponse(res, 405, "Method not allowed");
  }

  let body;
  try {
    body = await readJsonBody(req, MAX_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }

  const normalized = normalizeAdjudicationRequest(body);
  if (!normalized.ok) {
    return jsonResponse(res, 400, { error: normalized.error });
  }

  let oidcClaims;
  try {
    oidcClaims = await verifyGitHubActionsOidc(req.headers.authorization, {
      eventName: normalized.request.eventName,
      workflowRunId: normalized.request.workflowRunId,
      baseSha: normalized.request.baseSha,
      headSha: normalized.request.headSha,
    });
  } catch (error) {
    return jsonResponse(res, 401, { error: error.message });
  }

  try {
    const response = await adjudicate(normalized.request, oidcClaims);
    return jsonResponse(res, 200, response);
  } catch (error) {
    console.error("[FirstPrinciples] Adjudication failed:", error.message);
    return jsonResponse(res, 502, { error: "First Principles adjudication failed" });
  }
}

export async function handleFirstPrinciplesPolicy(url, req, res) {
  if (req.method !== "GET") {
    return textResponse(res, 405, "Method not allowed");
  }

  try {
    const manifest = await attestPayload(buildPolicyPayload());
    recordManifestAttestation({ surface: "policy", status: "success" });
    return jsonResponse(res, 200, manifest);
  } catch (error) {
    recordManifestAttestation({ surface: "policy", status: "failed", error });
    console.error("[FirstPrinciples] Policy manifest failed:", error.message);
    return jsonResponse(res, 503, { error: "First Principles policy unavailable" });
  }
}

async function adjudicate(request, oidcClaims) {
  const diffDigest = sha256Digest(request.diff);
  const changedFilesDigest = sha256Digest(canonicalStringify(request.changedFiles));
  const prompt = buildFirstPrinciplesPrompt({ ...request, diffDigest });
  const rawDecision = await generateFirstPrinciplesContent(prompt);
  const decision = parseFirstPrinciplesDecision(rawDecision);

  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + 30 * 60 * 1000);
  const payload = {
    schema: ADJUDICATION_SCHEMA,
    repository: request.repository,
    eventName: request.eventName,
    pullNumber: request.pullNumber,
    baseSha: request.baseSha,
    headSha: request.headSha,
    workflowRunId: String(request.workflowRunId),
    workflowRunUrl: request.workflowRunUrl || null,
    nonce: request.nonce,
    changedFiles: request.changedFiles,
    changedFilesDigest,
    diffDigest,
    complianceSummaryDigest: request.complianceSummaryDigest || null,
    complianceRulesDigest: request.complianceRulesDigest || null,
    decision: decision.decision,
    reasoning: decision.reasoning,
    violatedPrinciples: decision.violatedPrinciples,
    remediation: decision.remediation,
    policyVersion: FIRST_PRINCIPLES_POLICY_VERSION,
    promptDigest: FIRST_PRINCIPLES_PROMPT_DIGEST,
    responseMimeType: FIRST_PRINCIPLES_RESPONSE_MIME_TYPE,
    responseSchemaDigest: FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST,
    model: FIRST_PRINCIPLES_MODEL,
    modelPolicyDigest: FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
    temperature: FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
    vertexLocation: FIRST_PRINCIPLES_VERTEX_LOCATION,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    githubOidc: {
      repository: oidcClaims.repository,
      workflowRef: oidcClaims.job_workflow_ref,
      eventName: oidcClaims.event_name,
      runId: String(oidcClaims.run_id),
      runNumber: String(oidcClaims.run_number || ""),
      actor: oidcClaims.actor,
      ref: oidcClaims.ref,
      sha: oidcClaims.sha,
    },
  };

  return attestPayload(payload);
}

function buildPolicyPayload() {
  const claims = getLauncherAttestationClaims();
  const imageSignature = claims.submods?.container?.image_signatures?.[0] || null;
  const routeRegistry = getRouteRegistryStatus();
  const governanceManifest = buildGovernanceManifestPayload();
  return {
    schema: POLICY_SCHEMA,
    policyVersion: FIRST_PRINCIPLES_POLICY_VERSION,
    imageDigest: getAttestedImageDigest(),
    firstPrinciplesPromptDigest: FIRST_PRINCIPLES_PROMPT_DIGEST,
    firstPrinciplesResponseMimeType: FIRST_PRINCIPLES_RESPONSE_MIME_TYPE,
    firstPrinciplesResponseSchemaDigest: FIRST_PRINCIPLES_RESPONSE_SCHEMA_DIGEST,
    githubWorkflowIdentity: FIRST_PRINCIPLES_WORKFLOW_IDENTITY,
    cosignKmsKeyFingerprint: imageSignature?.key_id || null,
    cosignKmsSignatureAlgorithm: imageSignature?.signature_algorithm || null,
    routeTrustAnchorsDigest: routeRegistry.trustAnchorsDigest,
    routeBundleDigest: routeRegistry.routeBundleDigest,
    modelPolicyDigest: FIRST_PRINCIPLES_MODEL_POLICY_DIGEST,
    governance: {
      status: governanceManifest.status,
      epoch: governanceManifest.epoch,
      governanceKeyId: governanceManifest.governanceKeyId,
      lineageDigest: governanceManifest.lineageDigest,
      governanceManifestDigest: sha256Digest(canonicalStringify(governanceManifest)),
      modelPolicyDigest: governanceManifest.modelPolicyDigest,
      healthStatus: governanceManifest.health?.status || null,
      selfHealingProposalDigests: governanceManifest.selfHealing?.openProposalDigests || [],
      noAdminRecovery: true,
      githubSuperUserTrusted: false,
      gcpOwnerTrusted: false,
    },
    routeRegistrySummary: {
      tenantApiRouteCount: routeRegistry.tenantApiRouteCount,
      deployWebhookRouteCount: routeRegistry.deployWebhookRouteCount,
      routes: routeRegistry.routeSummaries.map((route) => ({
        schema: route.schema,
        tenant: route.tenant,
        version: route.version,
        digest: route.digest,
        expiresAt: route.expiresAt,
      })),
    },
    model: FIRST_PRINCIPLES_MODEL,
    temperature: FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
    vertexLocation: FIRST_PRINCIPLES_VERTEX_LOCATION,
    genaiSdkRequired: true,
    issuedAt: new Date().toISOString(),
  };
}

async function attestPayload(payload) {
  const payloadDigest = sha256Digest(canonicalStringify(payload));
  return {
    payload,
    payloadDigest,
    attestationToken: await requestAttestationToken([payloadDigest]),
    attestationBinding: "google-confidential-space-eat-nonce-sha256",
  };
}

function normalizeAdjudicationRequest(body) {
  if (!body || typeof body !== "object") {
    return { ok: false, error: "Request body must be a JSON object" };
  }

  const repository = body.repository || [body.owner, body.repo].filter(Boolean).join("/");
  const eventName = body.eventName || body.event_name;
  const headSha = body.headSha || body.head_sha;
  const diff = body.diff;
  const workflowRunId = body.workflowRunId || body.workflow_run_id;
  const nonce = body.nonce;
  const changedFiles = Array.isArray(body.changedFiles || body.changed_files)
    ? body.changedFiles || body.changed_files
    : [];

  if (repository !== "FemLed/auth-broker-tee") return { ok: false, error: "repository must be FemLed/auth-broker-tee" };
  if (!["pull_request", "pull_request_target", "push"].includes(eventName)) {
    return { ok: false, error: "eventName must be pull_request, pull_request_target, or push" };
  }
  if (!/^[a-f0-9]{40}$/i.test(headSha || "")) return { ok: false, error: "headSha must be a 40 character git SHA" };
  if (body.baseSha && !/^[a-f0-9]{40}$/i.test(body.baseSha)) return { ok: false, error: "baseSha must be a 40 character git SHA" };
  if (typeof diff !== "string" || diff.length === 0) return { ok: false, error: "diff must be a non-empty string" };
  if (Buffer.byteLength(diff, "utf8") > MAX_DIFF_BYTES) return { ok: false, error: `diff must be <= ${MAX_DIFF_BYTES} bytes` };
  if (!workflowRunId) return { ok: false, error: "workflowRunId is required" };
  if (typeof nonce !== "string" || nonce.length < 16 || nonce.length > 128) return { ok: false, error: "nonce must be 16-128 characters" };
  if (changedFiles.length > MAX_CHANGED_FILES || changedFiles.some((file) => typeof file !== "string" || file.length > 512)) {
    return { ok: false, error: "changedFiles contains invalid entries" };
  }

  return {
    ok: true,
    request: {
      repository,
      eventName,
      pullNumber: body.pullNumber || body.pull_number || null,
      baseSha: body.baseSha || body.base_sha || null,
      headSha,
      changedFiles,
      diff,
      complianceSummaryDigest: body.complianceSummaryDigest || body.compliance_summary_digest || null,
      complianceRulesDigest: body.complianceRulesDigest || body.compliance_rules_digest || null,
      workflowRunId: String(workflowRunId),
      workflowRunUrl: body.workflowRunUrl || body.workflow_run_url || null,
      nonce,
    },
  };
}

function readJsonBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let data = "";
    let bytes = 0;
    req.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        reject(new Error(`Request body exceeds ${maxBytes} bytes`));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", () => reject(new Error("Request body read failed")));
  });
}

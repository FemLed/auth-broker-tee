import crypto from "node:crypto";
import { canonicalStringify, sha256Digest, verifyCanonicalPayload } from "./canonical-json.js";
import { jsonResponse, textResponse } from "./http-helpers.js";
import { verifyGitHubActionsOidc } from "./github-oidc.js";
import { generateFirstPrinciplesContent } from "./vertex-gemini.js";
import {
  buildGovernanceSuccessorPrompt,
  parseFirstPrinciplesDecision,
} from "./first-principles-review.js";
import { inspectCandidateImageEvidence } from "./governance-image-inspection.js";
import {
  attestGovernanceManifest,
  bootstrapGenesisFromAttestedApproval,
  completeActivation,
  createActivationChallenge,
  finalizeActivation,
  issuePreapprovalCertificate,
  issueTenantAdmissionCertificate,
  applyActivationBundle,
} from "./governance-state.js";
import {
  recordRepairArtifact,
  recordRepairCandidateSubmission,
} from "./governance-repair-jobs.js";
import { recordManifestAttestation } from "./governance-monitor.js";
import { initializeRouteRegistry } from "./route-registry.js";

const MAX_GOVERNANCE_BODY_BYTES = 2 * 1024 * 1024;
const MAX_GOVERNANCE_CHALLENGE_BODY_BYTES = 16 * 1024;
const GOVERNANCE_OIDC_AUDIENCE = "https://oauth-tee.femled.ai/governance";
const GOVERNANCE_WORKFLOW_REFS = [
  "FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master",
];
const GOVERNANCE_ALLOWED_EVENTS = new Set(["push"]);
const PREAPPROVAL_CHALLENGE_PURPOSE = "governance.preapprove";
const TENANT_REGISTRATION_SCHEMA = "femled.auth_broker.tenant_registration.v1";
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const CHALLENGE_MAX_RECORDS = 200;
const COARSE_RATE_LIMIT = { windowMs: 60 * 1000, max: 120 };
const AUTHENTICATED_RATE_LIMITS = {
  challenge: { windowMs: 10 * 60 * 1000, max: 30 },
  mutation: { windowMs: 10 * 60 * 1000, max: 60 },
  gemini: { windowMs: 30 * 60 * 1000, max: 6 },
};

const coarseRateBuckets = new Map();
const authenticatedRateBuckets = new Map();
const governanceChallenges = new Map();

let verifyGovernanceOidc = verifyGitHubActionsOidc;
let governanceNow = () => new Date();

export async function handleGovernanceManifest(req, res) {
  if (req.method !== "GET") return textResponse(res, 405, "Method not allowed");
  try {
    const manifest = await attestGovernanceManifest();
    recordManifestAttestation({ surface: "governance", status: "success" });
    return jsonResponse(res, 200, manifest);
  } catch (error) {
    recordManifestAttestation({ surface: "governance", status: "failed", error });
    console.error("[Governance] Manifest failed:", error.message);
    return jsonResponse(res, 503, { error: "Governance manifest unavailable" });
  }
}

export async function handleGovernancePreapproval(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "preapprove")) return;
  const authContext = await authorizeGovernanceRequest(req, res, { rateLimitProfile: "gemini" });
  if (!authContext) return;
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }

  let challenge;
  try {
    challenge = consumeGovernanceChallenge({
      body,
      authContext,
      purpose: PREAPPROVAL_CHALLENGE_PURPOSE,
      requestDigest: digestPreapprovalRequest(body),
    });
  } catch (error) {
    return jsonResponse(res, 401, { error: error.message });
  }

  try {
    assertPreapprovalProvenanceMatchesAuth(body, authContext);
    const candidate = await inspectCandidateImageEvidence(body);
    if (candidate.hardCheckResults.status !== "passed") {
      return jsonResponse(res, 422, {
        decision: "REQUEST_CHANGES",
        reason: "candidate failed governance hard checks",
        hardCheckResults: candidate.hardCheckResults,
      });
    }
    const prompt = buildGovernanceSuccessorPrompt({
      candidate,
      hardCheckResults: candidate.hardCheckResults,
      sourceBundle: body.sourceBundle || null,
    });
    const rawDecision = await generateFirstPrinciplesContent(prompt);
    const aiDecision = parseFirstPrinciplesDecision(rawDecision);
    const aiResponseDigest = sha256Digest(rawDecision);
    if (aiDecision.decision !== "APPROVE") {
      return jsonResponse(res, 200, {
        decision: "REQUEST_CHANGES",
        aiDecision,
        aiResponseDigest,
      });
    }
    const preapproval = await issuePreapprovalCertificate({
      candidate,
      hardCheckResults: candidate.hardCheckResults,
      aiDecision,
      aiResponseDigest,
      nonce: challenge.nonce,
      challengeDigest: challenge.challengeDigest,
      requestDigest: challenge.requestDigest,
      authorizedCallerDigest: authContext.subjectDigest,
      authorizedWorkflowRef: authContext.workflowRef,
      authorizedRunId: authContext.runId,
    });
    return jsonResponse(res, 200, {
      decision: "APPROVE",
      candidate,
      aiDecision,
      aiResponseDigest,
      preapproval,
      finalAcceptance: "not_granted_until_activation_complete",
      nextStep: "Present an attested inactive candidate to /governance/activation-complete for final Gemini successor arbitration.",
    });
  } catch (error) {
    console.error("[Governance] Preapproval failed:", error.message);
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleGovernanceChallenge(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "challenge")) return;
  const authContext = await authorizeGovernanceRequest(req, res, { rateLimitProfile: "challenge" });
  if (!authContext) return;

  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_CHALLENGE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }

  try {
    const challenge = createGovernanceChallenge({ body, authContext });
    return jsonResponse(res, 200, { challenge });
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleGenesisBootstrap(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
  try {
    const manifest = await bootstrapGenesisFromAttestedApproval(body);
    let routeRegistry = null;
    let routeRegistryError = null;
    try {
      routeRegistry = await initializeRouteRegistry();
    } catch (error) {
      routeRegistryError = error.message;
    }
    return jsonResponse(res, 200, {
      status: "active",
      manifest,
      routeRegistry,
      routeRegistryError,
      authority: "genesis_bootstrapped_from_fresh_attested_tee_approval",
    });
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleActivationOffer(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "activation-offer")) return;
  const authContext = await authorizeGovernanceRequest(req, res, { rateLimitProfile: "mutation" });
  if (!authContext) return;
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
  try {
    const challenge = createActivationChallenge(body);
    return jsonResponse(res, 200, challenge);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleActivationComplete(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "activation-complete")) return;
  const authContext = await authorizeGovernanceRequest(req, res, { rateLimitProfile: "gemini" });
  if (!authContext) return;
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
  try {
    const bundle = await completeActivation(body);
    return jsonResponse(res, 200, {
      ...bundle,
      finalAcceptance: "pending_candidate_apply_and_predecessor_finalize",
    });
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleActivationFinalize(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "activation-finalize")) return;
  const authContext = await authorizeGovernanceRequest(req, res, { rateLimitProfile: "mutation" });
  if (!authContext) return;
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
  try {
    return jsonResponse(res, 200, {
      ...(await finalizeActivation(body)),
      finalAcceptance: "granted_after_candidate_activation_proof",
    });
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleActivationApply(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "activation-apply")) return;
  const authContext = await authorizeGovernanceRequest(req, res, { rateLimitProfile: "mutation" });
  if (!authContext) return;
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
  try {
    const manifest = await applyActivationBundle(body);
    await initializeRouteRegistry();
    return jsonResponse(res, 200, manifest);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleTenantAdmission(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "tenant-admission")) return;
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
  try {
    const registrationProof = verifyTenantRegistrationEnvelope(body.registrationEnvelope, body);
    const admission = await issueTenantAdmissionCertificate({
      ...body,
      registrationProofDigest: registrationProof.payloadDigest,
    });
    return jsonResponse(res, 200, {
      status: "admitted",
      admission,
      registrationProofDigest: registrationProof.payloadDigest,
      authority: "tenant_signed_registration_and_active_tee_governance_key",
      nextStep: "Tenant signs a route envelope with its tenant-held private key and publishes {admissionEnvelope, routeEnvelope} to the untrusted route document store.",
    });
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleRepairArtifact(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "repair-artifact")) return;
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
  try {
    return jsonResponse(res, 200, {
      status: "recorded",
      repairJob: recordRepairArtifact(body, { callbackToken: getBearerToken(req) }),
      authority: "artifact_record_only_not_activation",
    });
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

export async function handleRepairCandidate(req, res) {
  if (req.method !== "POST") return textResponse(res, 405, "Method not allowed");
  if (!consumeCoarseRateLimit(req, res, "repair-candidate")) return;
  let body;
  try {
    body = await readJsonBody(req, MAX_GOVERNANCE_BODY_BYTES);
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
  try {
    return jsonResponse(res, 200, {
      status: "recorded",
      repairJob: recordRepairCandidateSubmission(body, { callbackToken: getBearerToken(req) }),
      nextStep: "Submit the exact candidate image and source bundle to /governance/preapprove; this record is not preapproval or activation.",
      authority: "candidate_record_only_not_activation",
    });
  } catch (error) {
    return jsonResponse(res, 400, { error: error.message });
  }
}

function assertPreapprovalProvenanceMatchesAuth(body, authContext) {
  const sourceBundle = body?.sourceBundle || {};
  const workflowRunId = sourceBundle.workflowRunId ? String(sourceBundle.workflowRunId) : "";
  const headSha = sourceBundle.headSha || sourceBundle.sourceRevision || "";
  const oidcRunId = authContext.runId || "";
  const oidcSha = authContext.claims?.sha || "";

  if (!workflowRunId || workflowRunId !== oidcRunId) {
    throw new Error("preapproval sourceBundle.workflowRunId must match GitHub OIDC run_id");
  }
  if (!/^[a-f0-9]{40}$/i.test(headSha) || headSha !== oidcSha) {
    throw new Error("preapproval sourceBundle.headSha must match GitHub OIDC sha");
  }
  const expectedProvenanceDigest = sha256Digest(canonicalStringify({
    workflowRunId,
    headSha,
  }));
  if (sourceBundle.provenanceDigest !== expectedProvenanceDigest) {
    throw new Error("preapproval sourceBundle provenanceDigest must bind workflowRunId and headSha");
  }
}

function verifyTenantRegistrationEnvelope(envelope, admissionRequest, { now = governanceNow() } = {}) {
  if (!envelope || typeof envelope !== "object") {
    throw new Error("tenant admission requires registrationEnvelope");
  }
  assertExactKeys(envelope, ["payload", "payloadDigest", "signature"], "tenant registration envelope");
  const payload = envelope.payload;
  if (!payload || typeof payload !== "object") {
    throw new Error("tenant registration payload must be an object");
  }
  if (payload.schema !== TENANT_REGISTRATION_SCHEMA) {
    throw new Error(`tenant registration schema must be ${TENANT_REGISTRATION_SCHEMA}`);
  }
  if (envelope.payloadDigest !== sha256Digest(canonicalStringify(payload))) {
    throw new Error("tenant registration payloadDigest mismatch");
  }
  assertTenantRegistrationMatchesRequest(payload, admissionRequest);
  assertTenantRegistrationFresh(payload, { now });

  const signature = envelope.signature;
  if (!signature || typeof signature !== "object") {
    throw new Error("tenant registration signature must be an object");
  }
  assertExactKeys(signature, ["alg", "keyId", "sig"], "tenant registration signature");
  const key = payload.tenantRouteSigningKeys.find((candidate) =>
    candidate.keyId === signature.keyId && candidate.alg === signature.alg
  );
  if (!key) {
    throw new Error("tenant registration signature key must be one of tenantRouteSigningKeys");
  }
  if (!verifyTenantRegistrationSignature(payload, signature, key)) {
    throw new Error("tenant registration signature verification failed");
  }
  return {
    payload,
    payloadDigest: envelope.payloadDigest,
  };
}

function assertTenantRegistrationMatchesRequest(payload, request) {
  const expected = {
    tenant: request.tenant,
    tenantRouteSigningKeys: request.tenantRouteSigningKeys,
    minRouteVersion: request.minRouteVersion,
    allowedApiHosts: request.allowedApiHosts,
    allowedAppHosts: request.allowedAppHosts,
    allowedBrokerAudiences: request.allowedBrokerAudiences,
    ...(request.ttlMs ? { ttlMs: request.ttlMs } : {}),
  };
  const actual = {
    tenant: payload.tenant,
    tenantRouteSigningKeys: payload.tenantRouteSigningKeys,
    minRouteVersion: payload.minRouteVersion,
    allowedApiHosts: payload.allowedApiHosts,
    allowedAppHosts: payload.allowedAppHosts,
    allowedBrokerAudiences: payload.allowedBrokerAudiences,
    ...(payload.ttlMs ? { ttlMs: payload.ttlMs } : {}),
  };
  if (canonicalStringify(actual) !== canonicalStringify(expected)) {
    throw new Error("tenant registration payload must match admission request");
  }
}

function assertTenantRegistrationFresh(payload, { now }) {
  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  const nowMs = now.getTime();
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)) {
    throw new Error("tenant registration issuedAt and expiresAt must be ISO timestamps");
  }
  if (issuedAt > nowMs + 5 * 60 * 1000) {
    throw new Error("tenant registration issuedAt is too far in the future");
  }
  if (expiresAt <= nowMs) {
    throw new Error("tenant registration is expired");
  }
}

function verifyTenantRegistrationSignature(payload, signature, key) {
  if (signature.alg === "Ed25519") {
    return verifyCanonicalPayload(payload, signature.sig, key.publicKeyPem);
  }
  if (signature.alg === "ECDSA_P256_SHA256") {
    return crypto.verify(
      "sha256",
      Buffer.from(canonicalStringify(payload), "utf8"),
      crypto.createPublicKey(key.publicKeyPem),
      Buffer.from(signature.sig, "base64url")
    );
  }
  throw new Error("tenant registration signature alg must be Ed25519 or ECDSA_P256_SHA256");
}

async function authorizeGovernanceRequest(req, res, { rateLimitProfile = "mutation" } = {}) {
  let claims;
  try {
    claims = await verifyGovernanceOidc(req.headers.authorization, {
      audience: GOVERNANCE_OIDC_AUDIENCE,
      workflowRefs: GOVERNANCE_WORKFLOW_REFS,
      allowedEvents: GOVERNANCE_ALLOWED_EVENTS,
    });
  } catch (error) {
    return jsonResponse(res, 401, { error: error.message });
  }

  const subject = claims.sub || `${claims.repository || "unknown"}:${claims.run_id || "unknown"}`;
  const authContext = {
    subject,
    subjectDigest: sha256Digest(subject),
    workflowRef: claims.job_workflow_ref || null,
    runId: claims.run_id ? String(claims.run_id) : null,
    actor: claims.actor || null,
    claims,
  };
  const limit = AUTHENTICATED_RATE_LIMITS[rateLimitProfile] || AUTHENTICATED_RATE_LIMITS.mutation;
  const limited = consumeRateLimit(
    authenticatedRateBuckets,
    `${rateLimitProfile}:${authContext.subjectDigest}`,
    limit
  );
  if (!limited.allowed) {
    return jsonResponse(res, 429, {
      error: "Governance request rate limit exceeded",
      retryAfterSeconds: limited.retryAfterSeconds,
    });
  }
  return authContext;
}

function consumeCoarseRateLimit(req, res, routeName) {
  const limited = consumeRateLimit(
    coarseRateBuckets,
    `${routeName}:${clientAddress(req)}`,
    COARSE_RATE_LIMIT
  );
  if (!limited.allowed) {
    jsonResponse(res, 429, {
      error: "Governance request rate limit exceeded",
      retryAfterSeconds: limited.retryAfterSeconds,
    });
    return false;
  }
  return true;
}

function consumeRateLimit(buckets, key, { windowMs, max }, now = governanceNow().getTime()) {
  const cutoff = now - windowMs;
  const timestamps = (buckets.get(key) || []).filter((timestamp) => timestamp > cutoff);
  if (timestamps.length >= max) {
    const retryAfterMs = Math.max(1, timestamps[0] + windowMs - now);
    buckets.set(key, timestamps);
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
    };
  }
  timestamps.push(now);
  buckets.set(key, timestamps);
  return { allowed: true, retryAfterSeconds: 0 };
}

function clientAddress(req) {
  return req.socket?.remoteAddress || req.connection?.remoteAddress || "unknown";
}

function createGovernanceChallenge({ body, authContext, now = governanceNow() }) {
  if (!body || typeof body !== "object") {
    throw new Error("challenge request body must be an object");
  }
  if (body.purpose !== PREAPPROVAL_CHALLENGE_PURPOSE) {
    throw new Error(`challenge purpose must be ${PREAPPROVAL_CHALLENGE_PURPOSE}`);
  }
  if (!isSha256Digest(body.requestDigest)) {
    throw new Error("challenge requestDigest must be a sha256 digest");
  }
  pruneGovernanceChallenges(now);
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_MS).toISOString();
  const challengePayload = {
    schema: "femled.tee.governance.challenge.v1",
    nonce: crypto.randomBytes(32).toString("base64url"),
    purpose: body.purpose,
    requestDigest: body.requestDigest,
    authorizedCallerDigest: authContext.subjectDigest,
    authorizedWorkflowRef: authContext.workflowRef,
    authorizedRunId: authContext.runId,
    issuedAt,
    expiresAt,
  };
  const challenge = {
    ...challengePayload,
    challengeDigest: sha256Digest(canonicalStringify(challengePayload)),
  };
  governanceChallenges.set(challenge.nonce, {
    challenge,
    expiresAt: Date.parse(expiresAt),
    used: false,
  });
  trimGovernanceChallengeRecords();
  return challenge;
}

function consumeGovernanceChallenge({ body, authContext, purpose, requestDigest, now = governanceNow() }) {
  const challenge = body?.governanceChallenge || body?.challenge;
  if (!challenge || typeof challenge !== "object") {
    throw new Error("Missing governance challenge");
  }
  if (!challenge.nonce || typeof challenge.nonce !== "string") {
    throw new Error("Invalid governance challenge");
  }
  const record = governanceChallenges.get(challenge.nonce);
  if (!record || record.used || record.expiresAt <= now.getTime()) {
    governanceChallenges.delete(challenge.nonce);
    throw new Error("Invalid or expired governance challenge");
  }
  const { challengeDigest, ...challengePayload } = challenge;
  const computedChallengeDigest = sha256Digest(canonicalStringify(challengePayload));
  if (challengeDigest !== computedChallengeDigest || challengeDigest !== record.challenge.challengeDigest) {
    throw new Error("Invalid governance challenge");
  }
  if (challenge.schema !== "femled.tee.governance.challenge.v1") {
    throw new Error("Invalid governance challenge");
  }
  if (challenge.purpose !== purpose) {
    throw new Error("Governance challenge purpose mismatch");
  }
  if (challenge.requestDigest !== requestDigest) {
    throw new Error("Governance challenge request digest mismatch");
  }
  if (challenge.authorizedCallerDigest !== authContext.subjectDigest) {
    throw new Error("Governance challenge caller mismatch");
  }
  if (challenge.authorizedWorkflowRef !== authContext.workflowRef) {
    throw new Error("Governance challenge workflow mismatch");
  }
  if (challenge.authorizedRunId !== authContext.runId) {
    throw new Error("Governance challenge run mismatch");
  }
  record.used = true;
  governanceChallenges.delete(challenge.nonce);
  return challenge;
}

function digestPreapprovalRequest(body) {
  const { governanceChallenge, challenge, ...request } = body || {};
  return sha256Digest(canonicalStringify(request));
}

function pruneGovernanceChallenges(now = governanceNow()) {
  const nowMs = now.getTime();
  for (const [nonce, record] of governanceChallenges.entries()) {
    if (record.used || record.expiresAt <= nowMs) {
      governanceChallenges.delete(nonce);
    }
  }
}

function trimGovernanceChallengeRecords() {
  while (governanceChallenges.size > CHALLENGE_MAX_RECORDS) {
    const oldestNonce = governanceChallenges.keys().next().value;
    if (!oldestNonce) return;
    governanceChallenges.delete(oldestNonce);
  }
}

function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/i.test(value);
}

function assertExactKeys(value, keys, label) {
  const actual = Object.keys(value || {}).sort();
  const expected = [...keys].sort();
  if (canonicalStringify(actual) !== canonicalStringify(expected)) {
    throw new Error(`${label} keys must be exactly: ${expected.join(", ")}`);
  }
}

export function resetGovernanceRouteSecurityForTests() {
  coarseRateBuckets.clear();
  authenticatedRateBuckets.clear();
  governanceChallenges.clear();
  verifyGovernanceOidc = verifyGitHubActionsOidc;
  governanceNow = () => new Date();
}

export function setGovernanceOidcVerifierForTests(verifier) {
  verifyGovernanceOidc = verifier || verifyGitHubActionsOidc;
}

export function setGovernanceRouteNowForTests(clock) {
  governanceNow = clock || (() => new Date());
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
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
        resolve(JSON.parse(data || "{}"));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", () => reject(new Error("Request body read failed")));
  });
}
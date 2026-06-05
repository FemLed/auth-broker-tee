import crypto from "node:crypto";

const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_OIDC_JWKS_URL = `${GITHUB_OIDC_ISSUER}/.well-known/jwks`;
const DEFAULT_AUDIENCE = "https://oauth-tee.femled.ai/first-principles";
const DEFAULT_REPOSITORY = "FemLed/auth-broker-tee";
const DEFAULT_WORKFLOW_REFS = [
  "FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master",
  "FemLed/auth-broker-tee/.github/workflows/tee-first-principles-review.yml@refs/heads/master",
];
const ALLOWED_EVENTS = new Set(["pull_request", "pull_request_target", "push"]);
const JWKS_CACHE_TTL_MS = 60 * 60 * 1000;

let jwksCache = null;
let jwksCacheExpiry = 0;

export async function verifyGitHubActionsOidc(authHeader, expected = {}) {
  const token = extractBearer(authHeader);
  if (!token) {
    throw new Error("Missing GitHub Actions OIDC bearer token");
  }

  const payload = await verifyJwtSignature(token);
  validateClaims(payload, expected);
  return payload;
}

function extractBearer(authHeader) {
  if (typeof authHeader !== "string") return null;
  const separator = authHeader.indexOf(" ");
  if (separator <= 0) return null;
  const scheme = authHeader.slice(0, separator);
  if (scheme.toLowerCase() !== "bearer") return null;
  const token = authHeader.slice(separator + 1).trim();
  return token || null;
}

async function fetchJWKS() {
  const now = Date.now();
  if (jwksCache && now < jwksCacheExpiry) {
    return jwksCache;
  }

  const response = await fetch(GITHUB_OIDC_JWKS_URL, {
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) {
    throw new Error(`GitHub OIDC JWKS fetch failed: ${response.status}`);
  }

  jwksCache = await response.json();
  jwksCacheExpiry = now + JWKS_CACHE_TTL_MS;
  return jwksCache;
}

function decodeJwtParts(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT: expected 3 parts");
  }

  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  const signatureBytes = Buffer.from(parts[2], "base64url");
  const signedData = Buffer.from(`${parts[0]}.${parts[1]}`);

  return { header, payload, signatureBytes, signedData };
}

async function verifyJwtSignature(jwt) {
  const { header, payload, signatureBytes, signedData } = decodeJwtParts(jwt);
  if (header.alg !== "RS256") {
    throw new Error(`Unexpected GitHub OIDC JWT algorithm: ${header.alg}`);
  }

  const jwks = await fetchJWKS();
  const jwk = jwks.keys?.find((key) => key.kid === header.kid);
  if (!jwk) {
    throw new Error(`No GitHub OIDC JWKS key found for kid: ${header.kid}`);
  }

  const keyObject = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const valid = crypto.verify("RSA-SHA256", signedData, keyObject, signatureBytes);
  if (!valid) {
    throw new Error("GitHub OIDC JWT signature verification failed");
  }

  return payload;
}

function validateClaims(payload, expected) {
  const now = Math.floor(Date.now() / 1000);
  const expectedAudience = expected.audience || DEFAULT_AUDIENCE;
  const expectedRepository = expected.repository || DEFAULT_REPOSITORY;
  const expectedWorkflowRefs = expected.workflowRefs || DEFAULT_WORKFLOW_REFS;
  const allowedEvents = expected.allowedEvents || ALLOWED_EVENTS;

  const failures = [];
  if (payload.iss !== GITHUB_OIDC_ISSUER) failures.push(`iss must be ${GITHUB_OIDC_ISSUER}`);
  if (payload.aud !== expectedAudience) failures.push(`aud must be ${expectedAudience}`);
  if (payload.repository !== expectedRepository) failures.push(`repository must be ${expectedRepository}`);
  if (!expectedWorkflowRefs.includes(payload.job_workflow_ref)) {
    failures.push(`job_workflow_ref must be one of ${expectedWorkflowRefs.join(", ")}`);
  }
  if (!allowedEvents.has(payload.event_name)) failures.push(`event_name must be one of ${[...allowedEvents].join(", ")}`);
  if (payload.exp && payload.exp < now) failures.push("token is expired");
  if (payload.nbf && payload.nbf > now + 60) failures.push("token is not valid yet");
  if (payload.iat && payload.iat > now + 60) failures.push("token issued-at is in the future");

  if (expected.eventName && payload.event_name !== expected.eventName) {
    failures.push(`event_name must match request eventName ${expected.eventName}`);
  }
  if (expected.workflowRunId && String(payload.run_id) !== String(expected.workflowRunId)) {
    failures.push("run_id must match request workflowRunId");
  }
  if (payload.sha) {
    if (payload.event_name === "pull_request_target") {
      if (expected.baseSha && payload.sha !== expected.baseSha) {
        failures.push("sha must match request baseSha for pull_request_target");
      }
    } else if (expected.headSha && payload.sha !== expected.headSha) {
      failures.push("sha must match request headSha");
    }
  }

  if (failures.length > 0) {
    throw new Error(`GitHub OIDC claim validation failed: ${failures.join("; ")}`);
  }
}

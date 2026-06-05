import crypto from "node:crypto";

const CONFIDENTIAL_SPACE_ISSUER = "https://confidentialcomputing.googleapis.com";
const CONFIDENTIAL_SPACE_AUDIENCE = "https://oauth-tee.femled.ai";
const DISCOVERY_URL = "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration";
const JWKS_CACHE_TTL_MS = 60 * 60 * 1000;

let jwksCache = null;
let jwksCacheExpiry = 0;

export async function verifyConfidentialSpaceAttestation(jwt, {
  expectedNonce = null,
  expectedImageDigest = null,
  expectedAudience = CONFIDENTIAL_SPACE_AUDIENCE,
} = {}) {
  const payload = await verifyJwtSignature(jwt);
  validateConfidentialSpaceClaims(payload, { expectedAudience });
  if (expectedNonce && !nonceMatches(payload.eat_nonce, expectedNonce)) {
    throw new Error("Confidential Space attestation nonce mismatch");
  }
  if (expectedImageDigest && payload.submods?.container?.image_digest !== expectedImageDigest) {
    throw new Error("Confidential Space attestation image digest mismatch");
  }
  return payload;
}

export function validateConfidentialSpaceClaims(payload, { expectedAudience = CONFIDENTIAL_SPACE_AUDIENCE } = {}) {
  const failures = [];
  if (payload.iss !== CONFIDENTIAL_SPACE_ISSUER) failures.push(`iss must be ${CONFIDENTIAL_SPACE_ISSUER}`);
  if (payload.aud !== expectedAudience) failures.push(`aud must be ${expectedAudience}`);
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) failures.push("attestation is expired");
  if (payload.dbgstat !== "disabled-since-boot") failures.push("TEE debug status is not disabled-since-boot");
  if (payload.swname !== "CONFIDENTIAL_SPACE") failures.push("attestation is not for Confidential Space");
  if (failures.length > 0) {
    throw new Error(`Confidential Space claim validation failed: ${failures.join("; ")}`);
  }
  return payload;
}

export function nonceMatches(eatNonce, expected) {
  if (Array.isArray(eatNonce)) return eatNonce.includes(expected);
  return eatNonce === expected;
}

async function verifyJwtSignature(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("attestation token is not a JWT");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  const signedData = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], "base64url");
  if (header.alg !== "RS256") throw new Error(`unexpected attestation JWT algorithm: ${header.alg}`);

  const jwks = await fetchJWKS();
  const jwk = jwks.keys?.find((key) => key.kid === header.kid);
  if (!jwk) throw new Error(`No Confidential Space JWKS key for kid ${header.kid}`);
  const valid = crypto.verify("RSA-SHA256", signedData, crypto.createPublicKey({ key: jwk, format: "jwk" }), signature);
  if (!valid) throw new Error("Confidential Space attestation signature verification failed");
  return payload;
}

async function fetchJWKS() {
  const now = Date.now();
  if (jwksCache && now < jwksCacheExpiry) return jwksCache;
  const discoveryResp = await fetch(DISCOVERY_URL, { signal: AbortSignal.timeout(5000) });
  if (!discoveryResp.ok) throw new Error(`Confidential Space OIDC discovery failed: ${discoveryResp.status}`);
  const discovery = await discoveryResp.json();
  const jwksResp = await fetch(discovery.jwks_uri, { signal: AbortSignal.timeout(5000) });
  if (!jwksResp.ok) throw new Error(`Confidential Space JWKS fetch failed: ${jwksResp.status}`);
  jwksCache = await jwksResp.json();
  jwksCacheExpiry = now + JWKS_CACHE_TTL_MS;
  return jwksCache;
}

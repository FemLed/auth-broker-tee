// External TEE renewer governance signer (auth-broker-tee port).
//
// Builds a signed envelope that authoritative-dns-tee's external-TEE-renewer
// trust path will accept for narrow `_acme-challenge.oauth-tee.femled.ai`
// add/remove changes. The envelope binds a Confidential Space attestation
// token (issued fresh per envelope, with the request nonce as eat_nonce) to
// the canonical canonicalStringify of the request payload, signed by a
// KMS-backed ECDSA P-256 key whose fingerprint is image-baked into
// authoritative-dns-tee.
//
// Copy-not-share with coach-email-tee/src/renewer-governance-signer.js: the
// two TEE images are independently lineaged; both must drift independently
// rather than rely on a runtime cross-image dependency.

import crypto from "node:crypto";
import { canonicalStringify, publicKeyFingerprint, sha256Digest } from "./canonical-json.js";
import { requestAttestationToken } from "./attestation.js";
import {
  getAttestedImageDigest,
  kmsAsymmetricSign,
  kmsGetPublicKey,
} from "./gcp-auth.js";

const ENVELOPE_SCHEMA = "femled.authoritative_dns_tee.external_tee_renewer.envelope.v1";
const PAYLOAD_SCHEMA = "femled.authoritative_dns_tee.external_tee_renewer.payload.v1";
const VALIDITY_MS = 5 * 60 * 1000;
const RENEWER_CALLER_NAME = "auth-broker-tee";
const RENEWER_HOST_FQDN = "oauth-tee.femled.ai.";
const RENEWER_ATTESTATION_AUDIENCE = process.env.RENEWER_ATTESTATION_AUDIENCE || "https://ns1.femled.ai/renewer";
const RENEWER_KMS_SIGNER_KEY_VERSION = process.env.RENEWER_KMS_SIGNER_KEY_VERSION || "";

let cachedSignerPublicKeyPem = null;

export async function getSignerPublicKeyPem() {
  if (cachedSignerPublicKeyPem) return cachedSignerPublicKeyPem;
  if (!RENEWER_KMS_SIGNER_KEY_VERSION) {
    throw new Error("RENEWER_KMS_SIGNER_KEY_VERSION is not configured");
  }
  cachedSignerPublicKeyPem = await kmsGetPublicKey(RENEWER_KMS_SIGNER_KEY_VERSION);
  return cachedSignerPublicKeyPem;
}

export function resetRenewerSignerCacheForTests() {
  cachedSignerPublicKeyPem = null;
}

export async function buildRenewerEnvelope({ change, route = "/governance/routine-zone-change-renewer", now = new Date() }) {
  if (!RENEWER_KMS_SIGNER_KEY_VERSION) throw new Error("RENEWER_KMS_SIGNER_KEY_VERSION is not configured");
  // Read the image digest STRICTLY from the launcher attestation token. Any
  // env-var override would be an operator backdoor: a GCP admin could set
  // it to spoof a different image digest into the signed envelope, which
  // authoritative-dns-tee's allow-list pins to the running image. Trust
  // ONLY the hardware-attested value.
  const callerImageDigest = getAttestedImageDigest();
  if (!callerImageDigest) throw new Error("renewer envelope requires attested caller image digest");
  const publicKeyPem = await getSignerPublicKeyPem();
  const requestNonce = crypto.randomBytes(32).toString("base64url");
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + VALIDITY_MS).toISOString();
  const attestationToken = await requestAttestationToken([requestNonce], { audience: RENEWER_ATTESTATION_AUDIENCE });
  const attestationDigest = sha256Digest(Buffer.from(String(attestationToken || ""), "utf8"));
  const normalizedChange = normalizeChangeForEnvelope(change);
  const changeDigest = sha256Digest(canonicalStringify(normalizedChange));
  const payload = {
    schema: PAYLOAD_SCHEMA,
    callerName: RENEWER_CALLER_NAME,
    callerImageDigest,
    attestationToken,
    attestationDigest,
    route,
    change: normalizedChange,
    changeDigest,
    requestNonce,
    issuedAt,
    expiresAt,
  };
  const canonical = canonicalStringify(payload);
  const signatureBytes = await kmsAsymmetricSign(RENEWER_KMS_SIGNER_KEY_VERSION, Buffer.from(canonical));
  // auth-broker-tee's publicKeyFingerprint returns hex without the "sha256:"
  // prefix; the DNS-TEE verifier expects publicKeyId to be the prefixed form.
  return {
    schema: ENVELOPE_SCHEMA,
    payload,
    payloadDigest: sha256Digest(canonical),
    signatureAlgorithm: "ECDSA_P256_SHA256",
    publicKeyPem,
    publicKeyId: `sha256:${publicKeyFingerprint(publicKeyPem)}`,
    signature: signatureBytes.toString("base64url"),
  };
}

export const RENEWER_HOST = RENEWER_HOST_FQDN;

function normalizeChangeForEnvelope(change) {
  if (!change || typeof change !== "object") throw new Error("renewer change must be an object");
  const op = String(change.op || "").toLowerCase();
  const type = String(change.type || "").toUpperCase();
  const name = ensureFqdn(change.name);
  const ttl = Number(change.ttl);
  if (!Number.isInteger(ttl)) throw new Error("renewer change ttl must be an integer");
  const values = Array.isArray(change.values) ? change.values.map((value) => String(value)) : [];
  return { op, name, type, class: "IN", ttl, values };
}

function ensureFqdn(name) {
  const value = String(name || "").trim().toLowerCase();
  if (!value) throw new Error("renewer change name is required");
  return value.endsWith(".") ? value : `${value}.femled.ai.`;
}

// Sealed TLS capsule: the only at-rest form of this TEE's TLS material.
//
// Envelope shape: the leaf key + cert chain are AES-256-GCM encrypted
// in-enclave under a fresh 32-byte DEK; the DEK (and ONLY the DEK -- never the
// TLS key) is wrapped by the per-service KMS ENCRYPT_DECRYPT sealing key.
// Decrypt IAM on that key is granted solely to the WIF principalSet keyed by
// attribute.image_digest for this service's digest window (active image +
// registered roll candidates), so unsealing requires a fresh Confidential
// Space attestation of a measured lineage image. Confidential Space exposes no
// vTPM to workloads; this attestation-gated KMS unwrap is the measured-boot
// sealing equivalent.
//
// The capsule is the carry-over vehicle for lineage continuity: successor
// activations, roll candidates, and same-image restarts unseal it and keep
// serving the existing in-enclave cert instead of minting a fresh ACME cert.
// The GCM AAD binds {schema, service, host, lineageId} where lineageId is the
// governance lineage anchor (the genesis certificate's payloadDigest -- the
// broker's KMS-backed governanceKeyId is shared across re-geneses of the same
// image, so the genesis cert digest is the unique per-lineage anchor), making
// the at-rest blob tamper-evidently tied to the lineage that sealed it; a
// genesis event always re-mints and re-seals under the new anchor (see
// acme-renewal.js reconcileTlsWithLineage).
//
// Storage reuses the governance state-capsule bucket (CAPSULE_BUCKET, baked in
// the Dockerfile) under a dedicated `tls/` object. The bucket is untrusted
// ciphertext transport. Plaintext TLS keys are never written to Secret
// Manager, GCS, or disk.

import crypto from "node:crypto";
import { canonicalStringify } from "./canonical-json.js";
import {
  kmsEncrypt,
  kmsDecrypt,
  readGcsObjectJson,
  writeGcsObjectJson,
} from "./gcp-auth.js";

export const TLS_CAPSULE_SCHEMA = "femled.tee.tls_capsule.v1";
const SERVICE_NAME = "auth-broker-tee";
const HOST = "oauth-tee.femled.ai";

// Image-baked trust roots (env overrides exist for tests/staging only; the
// launch policy does not expose them to operators).
const TLS_SEALING_KMS_KEY_NAME =
  process.env.TLS_SEALING_KMS_KEY_NAME ||
  "projects/prod-femled-couple-router/locations/us-west1/keyRings/auth-broker-acme-renewer/cryptoKeys/tls-sealing";
export const TLS_CAPSULE_OBJECT = "tls/oauth-tee.tls-capsule.v1.json";

function capsuleBucket() {
  return process.env.CAPSULE_BUCKET || "prod-femled-couple-router-auth-broker-tee-governance-capsules";
}

const defaultTransport = {
  kmsEncrypt: (keyName, plaintext) => kmsEncrypt(keyName, plaintext),
  kmsDecrypt: (keyName, ciphertext) => kmsDecrypt(keyName, ciphertext),
  readObject: (bucket, objectName) => readGcsObjectJson(bucket, objectName),
  writeObject: (bucket, objectName, value) => writeGcsObjectJson(bucket, objectName, value),
};
let transport = defaultTransport;

let lastSealAt = null;
let lastSealError = null;

export function setTlsCapsuleTransportForTests(overrides) {
  transport = overrides ? { ...defaultTransport, ...overrides } : defaultTransport;
}

export function resetTlsCapsuleStatusForTests() {
  lastSealAt = null;
  lastSealError = null;
}

export function getTlsSealingKmsKeyName() {
  return TLS_SEALING_KMS_KEY_NAME;
}

export function getTlsCapsuleLocation() {
  return { bucket: capsuleBucket(), object: TLS_CAPSULE_OBJECT };
}

function capsuleAad(lineageId) {
  return Buffer.from(canonicalStringify({
    schema: TLS_CAPSULE_SCHEMA,
    service: SERVICE_NAME,
    host: HOST,
    lineageId: lineageId ?? null,
  }), "utf8");
}

export async function sealTlsMaterial({ keyPem, certPem, mintedAt, lineageId = null }) {
  if (!keyPem || !certPem) throw new Error("sealTlsMaterial requires keyPem and certPem");
  const dek = crypto.randomBytes(32);
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
    cipher.setAAD(capsuleAad(lineageId));
    const plaintext = Buffer.from(canonicalStringify({
      keyPem,
      certPem,
      mintedAt: mintedAt || null,
      host: HOST,
    }), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const wrappedDek = await transport.kmsEncrypt(TLS_SEALING_KMS_KEY_NAME, dek);

    const capsule = {
      schema: TLS_CAPSULE_SCHEMA,
      service: SERVICE_NAME,
      host: HOST,
      lineageId: lineageId ?? null,
      mintedAt: mintedAt || null,
      sealedAt: new Date().toISOString(),
      wrappedDek: wrappedDek.toString("base64"),
      iv: iv.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      authTag: authTag.toString("base64"),
    };
    await transport.writeObject(capsuleBucket(), TLS_CAPSULE_OBJECT, capsule);
    lastSealAt = capsule.sealedAt;
    lastSealError = null;
    return { sealedAt: capsule.sealedAt, lineageId: capsule.lineageId };
  } catch (error) {
    lastSealError = { at: new Date().toISOString(), error: String(error.message || error).slice(0, 512) };
    throw error;
  } finally {
    dek.fill(0);
  }
}

// Returns the unsealed material or null when no capsule exists yet. Throws on
// an unreadable/undecryptable capsule (caller decides whether that means
// "mint fresh" or "fail the boot").
export async function unsealTlsMaterial() {
  const capsule = await transport.readObject(capsuleBucket(), TLS_CAPSULE_OBJECT);
  if (!capsule) return null;
  if (capsule.schema !== TLS_CAPSULE_SCHEMA) {
    throw new Error(`TLS capsule schema mismatch: ${capsule.schema}`);
  }
  if (capsule.service !== SERVICE_NAME || capsule.host !== HOST) {
    throw new Error("TLS capsule service/host mismatch");
  }
  for (const field of ["wrappedDek", "iv", "ciphertext", "authTag"]) {
    if (typeof capsule[field] !== "string" || capsule[field].length === 0) {
      throw new Error(`TLS capsule is missing ${field}`);
    }
  }

  // The wrap is always unwrapped against OUR image-baked sealing key; the
  // capsule cannot redirect us to a different KMS key.
  const dek = await transport.kmsDecrypt(TLS_SEALING_KMS_KEY_NAME, Buffer.from(capsule.wrappedDek, "base64"));
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", dek, Buffer.from(capsule.iv, "base64"));
    // AAD is rebuilt from the capsule's own claimed lineageId; the GCM tag
    // makes any tampering with that claim fail the decrypt.
    decipher.setAAD(capsuleAad(capsule.lineageId ?? null));
    decipher.setAuthTag(Buffer.from(capsule.authTag, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(capsule.ciphertext, "base64")),
      decipher.final(),
    ]);
    const payload = JSON.parse(plaintext.toString("utf8"));
    if (payload.host !== HOST) throw new Error("TLS capsule payload host mismatch");
    if (!payload.keyPem || !payload.certPem) throw new Error("TLS capsule payload is missing keyPem/certPem");
    return {
      keyPem: payload.keyPem,
      certPem: payload.certPem,
      mintedAt: payload.mintedAt || capsule.mintedAt || null,
      lineageId: capsule.lineageId ?? null,
      sealedAt: capsule.sealedAt || null,
    };
  } finally {
    dek.fill(0);
  }
}

export function getTlsCapsuleStatus() {
  return { lastSealAt, lastSealError };
}

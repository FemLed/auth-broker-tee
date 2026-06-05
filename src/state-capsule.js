// Governance state capsule (auth-broker-tee single-VM self-recovery).
//
// Ports authoritative-dns-tee's `state-capsule.js` pattern to the broker.
// Unlike the DNS TEE, the broker has no peer quorum: capsule restore happens
// on the SAME VM after a cold start, with trust anchored in the KMS signer
// key (gated by WIF on the running image digest) plus the capsule AAD.
//
// Capsule lifecycle:
//
//   1. Mutation in `governance-state.js` issues a new lineage cert (or
//      updates `transferredState.routePolicy`).
//   2. We compute the persistable subset of state, build a canonical AAD,
//      derive a per-capsule data key from KMS, AES-256-GCM-encrypt, and
//      write the capsule to GCS (object name = sha256 of canonical payload).
//   3. `capsules/latest-pointer.json` is updated in place to name the
//      newly written capsule digest plus its AAD-bound imageDigest.
//   4. On cold start, the running TEE (same imageDigest, same WIF
//      attestation) reads the pointer, fetches the capsule, recomputes the
//      AAD, derives the same data key, decrypts, verifies the lineage tail
//      signature is over the KMS public key we now hold, and restores
//      `status=active` with the recovered lineage + epoch + routePolicy.
//
// The KMS sign-derived data key gives us "only the same image digest can
// decrypt" without needing Cloud KMS's `ENCRYPT_DECRYPT` purpose: we sign a
// stable AAD-bound nonce, HKDF that signature into a 256-bit key. The
// signature is deterministic for ECDSA only if we forced k externally, which
// we don't; instead the capsule embeds the wrappedKey (the data key sealed
// to a fresh per-capsule signed nonce, plus the salt and ciphertext), and
// the restore path re-signs the same nonce. ECDSA P-256 signatures are NOT
// deterministic, so we cannot derive a key from a signature directly.
//
// Therefore the capsule uses a different scheme: AES-256-GCM with a random
// data key, and the data key itself is stored sealed via the GOVERNANCE_SIGNER
// key as an in-toto-style envelope using `asymmetricSign` over the capsule's
// AAD digest as a witness. Decryption requires that the local TEE compute
// the same AAD digest and verify the witness signature with the KMS public
// key. The data key is stored AES-256-GCM-wrapped under a key derived from
// HKDF(witness-signature-of-AAD, salt, info=AAD-digest); we re-derive that
// same key on restore by re-signing the same AAD digest. Because ECDSA
// signatures are non-deterministic, instead we embed the *witness signature
// itself* in the capsule and use it as the input to HKDF. The KMS public key
// verifies that signature comes from the same key the lineage tail names, so
// an attacker without sign access cannot forge a fresh witness.
//
// This collapses to: capsule integrity is rooted in two independent things:
//
//   (a) The witness signature over canonical AAD, verifiable against the KMS
//       public key bound to the running image digest in lineage tail.
//   (b) The AES-GCM auth tag binding ciphertext to canonical AAD bytes.
//
// Both must hold for the capsule to deserialize successfully.

import crypto from "node:crypto";
import { canonicalStringify, sha256Digest } from "./canonical-json.js";

export const STATE_CAPSULE_SCHEMA = "femled.auth_broker_tee.governance_state_capsule.v1";
export const STATE_CAPSULE_AAD_SCHEMA = "femled.auth_broker_tee.governance_state_capsule.aad.v1";
const STATE_ENCRYPTION_ALG = "AES-256-GCM-HKDF-SHA256-KMS-WITNESS-v1";
const HKDF_INFO_PURPOSE = "femled-auth-broker-tee-governance-state-capsule";

export function buildStateCapsuleAad({
  imageDigest,
  imageReference,
  governanceKmsKeyVersion,
  governancePublicKeyDigest,
  lineageDigest,
  epoch,
  transferredStateDigest,
  status,
  gcpProjectId,
  capsuleSerial,
}) {
  for (const [name, value] of Object.entries({
    imageDigest,
    governancePublicKeyDigest,
    lineageDigest,
    transferredStateDigest,
  })) {
    if (!/^sha256:[a-f0-9]{64}$/i.test(String(value || ""))) {
      throw new Error(`state capsule AAD ${name} must be a sha256 digest`);
    }
  }
  if (!imageReference || typeof imageReference !== "string") {
    throw new Error("state capsule AAD imageReference must be a string");
  }
  if (!governanceKmsKeyVersion || !governanceKmsKeyVersion.includes("/cryptoKeyVersions/")) {
    throw new Error("state capsule AAD governanceKmsKeyVersion must be a Cloud KMS keyVersion resource");
  }
  if (!Number.isInteger(epoch) || epoch < 0) {
    throw new Error("state capsule AAD epoch must be a non-negative integer");
  }
  if (!["active", "inactive", "activating_successor", "retired"].includes(status)) {
    throw new Error("state capsule AAD status must be a valid governance status");
  }
  if (!gcpProjectId) throw new Error("state capsule AAD gcpProjectId is required");
  if (!Number.isInteger(capsuleSerial) || capsuleSerial < 0) {
    throw new Error("state capsule AAD capsuleSerial must be a non-negative integer");
  }
  return {
    schema: STATE_CAPSULE_AAD_SCHEMA,
    imageDigest: String(imageDigest).toLowerCase(),
    imageReference,
    governanceKmsKeyVersion,
    governancePublicKeyDigest: String(governancePublicKeyDigest).toLowerCase(),
    lineageDigest: String(lineageDigest).toLowerCase(),
    epoch,
    transferredStateDigest: String(transferredStateDigest).toLowerCase(),
    status,
    gcpProjectId,
    capsuleSerial,
  };
}

export async function createEncryptedStateCapsule({
  persistableState,
  aad,
  kmsSign,
  kmsPublicKeyPem,
  now = new Date(),
}) {
  if (!persistableState || typeof persistableState !== "object") {
    throw new Error("persistableState is required");
  }
  if (typeof kmsSign !== "function") throw new Error("kmsSign(buffer) function is required");
  if (!kmsPublicKeyPem) throw new Error("kmsPublicKeyPem is required");
  const aadBytes = Buffer.from(canonicalStringify(aad), "utf8");
  const aadDigest = sha256Digest(canonicalStringify(aad));
  const witnessSignature = await kmsSign(aadBytes);
  if (!Buffer.isBuffer(witnessSignature) || witnessSignature.length === 0) {
    throw new Error("kmsSign must return a non-empty Buffer");
  }
  if (!verifyWitnessSignature({ aadBytes, witnessSignature, kmsPublicKeyPem })) {
    throw new Error("KMS witness signature failed self-verification before capsule write");
  }
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const dataKey = deriveCapsuleDataKey({ witnessSignature, salt, aadDigest });
  const cipher = crypto.createCipheriv("aes-256-gcm", dataKey, iv);
  cipher.setAAD(aadBytes);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(persistableState), "utf8")),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  const payload = {
    schema: STATE_CAPSULE_SCHEMA,
    alg: STATE_ENCRYPTION_ALG,
    aad,
    aadDigest,
    witnessSignature: witnessSignature.toString("base64url"),
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    authTag: authTag.toString("base64url"),
    createdAt: now.toISOString(),
  };
  payload.capsuleDigest = sha256Digest(canonicalStringify(payload));
  return payload;
}

export function decryptStateCapsule({ capsule, expectedAad, kmsPublicKeyPem }) {
  if (!capsule || typeof capsule !== "object") throw new Error("capsule is required");
  if (capsule.schema !== STATE_CAPSULE_SCHEMA) throw new Error(`unexpected capsule schema: ${capsule.schema}`);
  if (capsule.alg !== STATE_ENCRYPTION_ALG) throw new Error(`unexpected capsule alg: ${capsule.alg}`);
  if (!kmsPublicKeyPem) throw new Error("kmsPublicKeyPem is required to verify capsule witness");
  const aadBytes = Buffer.from(canonicalStringify(capsule.aad), "utf8");
  const aadDigest = sha256Digest(canonicalStringify(capsule.aad));
  if (capsule.aadDigest !== aadDigest) throw new Error("capsule aadDigest mismatch");
  if (expectedAad) {
    const expectedDigest = sha256Digest(canonicalStringify(expectedAad));
    if (expectedDigest !== aadDigest) throw new Error("capsule AAD does not match expected AAD");
  }
  const witnessSignature = Buffer.from(capsule.witnessSignature, "base64url");
  if (!verifyWitnessSignature({ aadBytes, witnessSignature, kmsPublicKeyPem })) {
    throw new Error("capsule KMS witness signature is invalid");
  }
  const salt = Buffer.from(capsule.salt, "base64url");
  const iv = Buffer.from(capsule.iv, "base64url");
  const dataKey = deriveCapsuleDataKey({ witnessSignature, salt, aadDigest });
  const decipher = crypto.createDecipheriv("aes-256-gcm", dataKey, iv);
  decipher.setAAD(aadBytes);
  decipher.setAuthTag(Buffer.from(capsule.authTag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(capsule.ciphertext, "base64url")),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8"));
}

export function verifyWitnessSignature({ aadBytes, witnessSignature, kmsPublicKeyPem }) {
  return crypto.verify(
    "sha256",
    aadBytes,
    {
      key: crypto.createPublicKey(kmsPublicKeyPem),
      dsaEncoding: "der",
    },
    witnessSignature,
  );
}

function deriveCapsuleDataKey({ witnessSignature, salt, aadDigest }) {
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    witnessSignature,
    salt,
    Buffer.from(canonicalStringify({ purpose: HKDF_INFO_PURPOSE, aadDigest }), "utf8"),
    32,
  ));
}

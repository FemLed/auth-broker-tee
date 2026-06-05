// KMS-backed governance signing key.
//
// Replaces the in-memory ed25519 governance signer with a Cloud KMS
// ASYMMETRIC_SIGN key (ECDSA P-256 over SHA-256) when
// `GOVERNANCE_KMS_SIGNER_KEY_VERSION` is configured. The activation X25519
// key stays in-memory: it is only used per-handoff during successor
// activation, never restored from capsule, and regenerating it on cold
// start is intentional (each fresh image proves it can mint a fresh handoff
// recipient key under its own attestation).
//
// The key material object returned here exposes the same interface as
// `createInMemoryGovernanceKeyMaterial`:
//
//   - governancePublicKeyPem / governanceKeyId
//   - activationPublicKeyPem / activationKeyId
//   - sign(payload)              -> base64url signature over canonical JSON
//   - encryptStateFor(...)       -> X25519/AES-GCM envelope (activation key)
//   - decryptState(...)          -> X25519/AES-GCM open (activation key)
//
// Plus two extras that govern capsule persistence:
//
//   - kind                   "kms-backed" vs "in-memory"
//   - kmsKeyVersion          for AAD binding & lineage tail validation
//   - signWithKms(buffer)    raw witness-style sign for state-capsule.js
//   - getKmsPublicKeyPem()   PEM cached after first warmup

import crypto from "node:crypto";
import { canonicalStringify, publicKeyFingerprint, sha256Digest } from "./canonical-json.js";
import { kmsAsymmetricSign, kmsGetPublicKey } from "./gcp-auth.js";

const STATE_ENCRYPTION_ALG = "X25519-HKDF-SHA256-AES-256-GCM";

export function isKmsGovernanceKeyConfigured() {
  return Boolean(process.env.GOVERNANCE_KMS_SIGNER_KEY_VERSION);
}

export async function createKmsBackedGovernanceKeyMaterial({
  keyVersionResource = process.env.GOVERNANCE_KMS_SIGNER_KEY_VERSION,
  kmsSign = kmsAsymmetricSign,
  kmsPublicKey = kmsGetPublicKey,
} = {}) {
  if (!keyVersionResource) {
    throw new Error("GOVERNANCE_KMS_SIGNER_KEY_VERSION is required to create KMS-backed governance key material");
  }
  if (!keyVersionResource.includes("/cryptoKeyVersions/")) {
    throw new Error("GOVERNANCE_KMS_SIGNER_KEY_VERSION must reference a specific cryptoKeyVersion");
  }
  const governancePublicKeyPem = await kmsPublicKey(keyVersionResource);
  if (!governancePublicKeyPem) {
    throw new Error("Cloud KMS returned no public key for governance signer");
  }
  const governanceKeyId = `sha256:${publicKeyFingerprint(governancePublicKeyPem)}`;
  const activation = crypto.generateKeyPairSync("x25519");
  const activationPublicKeyPem = activation.publicKey.export({ type: "spki", format: "pem" });
  const activationKeyId = `sha256:${publicKeyFingerprint(activationPublicKeyPem)}`;

  return Object.freeze({
    kind: "kms-backed",
    // signGovernancePayload reads this to label the envelope; without it
    // the envelope falsely claims Ed25519 even though the KMS key produces
    // DER-encoded ECDSA P-256 signatures over SHA-256. Node's
    // verifyGovernanceEnvelope path uses crypto.verify(null, ...) which
    // auto-routes by key type so a wrong label still verifies internally,
    // but the standalone verifier binary strictly checks alg == "Ed25519"
    // and would reject the cert.
    signatureAlgorithm: "ECDSA_P256_SHA256",
    kmsKeyVersion: keyVersionResource,
    governancePublicKeyPem,
    governanceKeyId,
    activationPublicKeyPem,
    activationKeyId,
    async sign(payload) {
      const canonical = Buffer.from(canonicalStringify(payload), "utf8");
      const signature = await kmsSign(keyVersionResource, canonical);
      return signature.toString("base64url");
    },
    async signWithKms(buffer) {
      if (!Buffer.isBuffer(buffer)) throw new Error("signWithKms requires a Buffer");
      return kmsSign(keyVersionResource, buffer);
    },
    async getKmsPublicKeyPem() {
      return governancePublicKeyPem;
    },
    decryptState(envelope, aad) {
      return decryptStateEnvelope({
        envelope,
        recipientPrivateKey: activation.privateKey,
        aad,
      });
    },
    encryptStateFor(recipientActivationPublicKeyPem, plaintext, aad) {
      return encryptStateEnvelope({
        senderPrivateKey: activation.privateKey,
        senderActivationPublicKeyPem: activationPublicKeyPem,
        recipientActivationPublicKeyPem,
        plaintext,
        aad,
      });
    },
  });
}

// Encrypted state envelope helpers (X25519+HKDF+AES-GCM). Copy-not-share
// from governance-crypto.js so the in-memory and KMS-backed key material
// formats stay interoperable for successor handoffs without circular
// imports.
function encryptStateEnvelope({
  senderPrivateKey,
  senderActivationPublicKeyPem,
  recipientActivationPublicKeyPem,
  plaintext,
  aad,
}) {
  const recipientPublicKey = crypto.createPublicKey(normalizePem(recipientActivationPublicKeyPem));
  const sharedSecret = crypto.diffieHellman({
    privateKey: senderPrivateKey,
    publicKey: recipientPublicKey,
  });
  const salt = crypto.randomBytes(32);
  const key = deriveStateKey(sharedSecret, salt, aad);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(canonicalStringify(aad || {}), "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(plaintext), "utf8")),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    schema: "femled.tee.governance.encrypted_state.v1",
    alg: STATE_ENCRYPTION_ALG,
    senderActivationPublicKeyPem,
    recipientActivationPublicKeyPem,
    aadDigest: sha256Digest(canonicalStringify(aad || {})),
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: tag.toString("base64url"),
  };
}

function decryptStateEnvelope({ envelope, recipientPrivateKey, aad }) {
  if (envelope?.alg !== STATE_ENCRYPTION_ALG) {
    throw new Error("unsupported governance state encryption envelope");
  }
  const aadDigest = sha256Digest(canonicalStringify(aad || {}));
  if (envelope.aadDigest !== aadDigest) {
    throw new Error("encrypted governance state AAD mismatch");
  }
  const senderPublicKey = crypto.createPublicKey(normalizePem(envelope.senderActivationPublicKeyPem));
  const sharedSecret = crypto.diffieHellman({
    privateKey: recipientPrivateKey,
    publicKey: senderPublicKey,
  });
  const key = deriveStateKey(sharedSecret, Buffer.from(envelope.salt, "base64url"), aad);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64url"));
  decipher.setAAD(Buffer.from(canonicalStringify(aad || {}), "utf8"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8"));
}

function deriveStateKey(sharedSecret, salt, aad) {
  return crypto.hkdfSync(
    "sha256",
    sharedSecret,
    salt,
    Buffer.from(canonicalStringify({
      purpose: "femled-tee-governance-state-transfer",
      aadDigest: sha256Digest(canonicalStringify(aad || {})),
    }), "utf8"),
    32,
  );
}

function normalizePem(value) {
  return value?.includes("\\n") ? value.replace(/\\n/g, "\n") : value;
}

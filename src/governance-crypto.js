import crypto from "node:crypto";
import {
  canonicalStringify,
  publicKeyFingerprint,
  sha256Digest,
} from "./canonical-json.js";

const ENVELOPE_SCHEMA = "femled.tee.governance.envelope.v1";
const STATE_ENCRYPTION_ALG = "X25519-HKDF-SHA256-AES-256-GCM";

export function createInMemoryGovernanceKeyMaterial() {
  const signing = crypto.generateKeyPairSync("ed25519");
  const activation = crypto.generateKeyPairSync("x25519");
  const governancePublicKeyPem = exportPublicPem(signing.publicKey);
  const activationPublicKeyPem = exportPublicPem(activation.publicKey);

  return Object.freeze({
    kind: "in-memory",
    signatureAlgorithm: "Ed25519",
    governancePublicKeyPem,
    governanceKeyId: `sha256:${publicKeyFingerprint(governancePublicKeyPem)}`,
    activationPublicKeyPem,
    activationKeyId: `sha256:${publicKeyFingerprint(activationPublicKeyPem)}`,
    sign(payload) {
      const canonical = Buffer.from(canonicalStringify(payload), "utf8");
      return crypto.sign(null, canonical, signing.privateKey).toString("base64url");
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

export function signGovernancePayload(payload, keyMaterial) {
  const payloadDigest = sha256Digest(canonicalStringify(payload));
  const algorithm = keyMaterial.signatureAlgorithm || "Ed25519";
  const finalize = (sig) => ({
    schema: ENVELOPE_SCHEMA,
    payload,
    payloadDigest,
    signingKeyId: keyMaterial.governanceKeyId,
    signature: {
      alg: algorithm,
      sig,
    },
  });
  const result = keyMaterial.sign(payload);
  if (result && typeof result.then === "function") {
    return result.then(finalize);
  }
  return finalize(result);
}

export function verifyGovernanceEnvelope(envelope, publicKeyPem, { now = new Date(), enforceExpiry = true } = {}) {
  if (!envelope || typeof envelope !== "object") {
    throw new Error("governance envelope must be an object");
  }
  if (envelope.schema !== ENVELOPE_SCHEMA) {
    throw new Error(`governance envelope schema mismatch: ${envelope.schema}`);
  }
  if (!envelope.payload || typeof envelope.payload !== "object") {
    throw new Error("governance envelope payload missing");
  }
  const expectedDigest = sha256Digest(canonicalStringify(envelope.payload));
  if (envelope.payloadDigest !== expectedDigest) {
    throw new Error(`governance payload digest mismatch: expected ${expectedDigest}, got ${envelope.payloadDigest}`);
  }
  const keyId = `sha256:${publicKeyFingerprint(publicKeyPem)}`;
  if (envelope.signingKeyId !== keyId) {
    throw new Error(`governance signing key mismatch: expected ${keyId}, got ${envelope.signingKeyId}`);
  }
  const alg = envelope.signature?.alg;
  if (!alg || typeof envelope.signature.sig !== "string") {
    throw new Error("governance signature is malformed");
  }
  if (alg !== "Ed25519" && alg !== "ECDSA_P256_SHA256") {
    throw new Error(`unsupported governance signature algorithm: ${alg}`);
  }
  const canonical = Buffer.from(canonicalStringify(envelope.payload), "utf8");
  const sigBytes = Buffer.from(envelope.signature.sig, "base64url");
  const publicKeyObject = crypto.createPublicKey(normalizePem(publicKeyPem));
  const valid = alg === "Ed25519"
    ? crypto.verify(null, canonical, publicKeyObject, sigBytes)
    : crypto.verify(
        "sha256",
        canonical,
        { key: publicKeyObject, dsaEncoding: "der" },
        sigBytes,
      );
  if (!valid) {
    throw new Error("governance signature verification failed");
  }
  if (enforceExpiry && envelope.payload.expiresAt && Date.parse(envelope.payload.expiresAt) <= now.getTime()) {
    throw new Error("governance certificate expired");
  }
  return envelope.payload;
}

export function buildActivationNonce(fields) {
  return sha256Digest(canonicalStringify({
    schema: "femled.tee.governance.activation_nonce.v1",
    ...fields,
  }));
}

export function encryptStateEnvelope({
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

export function decryptStateEnvelope({ envelope, recipientPrivateKey, aad }) {
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
    32
  );
}

function exportPublicPem(key) {
  return key.export({ type: "spki", format: "pem" });
}

function normalizePem(value) {
  return value?.includes("\\n") ? value.replace(/\\n/g, "\n") : value;
}

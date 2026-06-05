import crypto from "node:crypto";

export function canonicalize(value) {
  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }

  const out = {};
  for (const key of Object.keys(value).sort()) {
    const item = value[key];
    if (item !== undefined) {
      out[key] = canonicalize(item);
    }
  }
  return out;
}

export function canonicalStringify(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function sha256Digest(input) {
  return `sha256:${sha256Hex(input)}`;
}

export function signCanonicalPayload(payload, privateKeyPem) {
  const key = crypto.createPrivateKey(normalizePem(privateKeyPem));
  const canonical = Buffer.from(canonicalStringify(payload), "utf8");
  return crypto.sign(null, canonical, key).toString("base64url");
}

export function verifyCanonicalPayload(payload, signature, publicKeyPem) {
  const key = crypto.createPublicKey(normalizePem(publicKeyPem));
  const canonical = Buffer.from(canonicalStringify(payload), "utf8");
  return crypto.verify(null, canonical, key, Buffer.from(signature, "base64url"));
}

export function publicKeyFingerprint(publicKeyPem) {
  const key = crypto.createPublicKey(normalizePem(publicKeyPem));
  const der = key.export({ type: "spki", format: "der" });
  return sha256Hex(der);
}

export function publicKeyFromPrivateKey(privateKeyPem) {
  const privateKey = crypto.createPrivateKey(normalizePem(privateKeyPem));
  return crypto
    .createPublicKey(privateKey)
    .export({ type: "spki", format: "pem" });
}

export function normalizePem(value) {
  return value?.includes("\\n") ? value.replace(/\\n/g, "\n") : value;
}

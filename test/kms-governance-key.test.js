import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createKmsBackedGovernanceKeyMaterial } from "../src/kms-governance-key.js";
import { signGovernancePayload, verifyGovernanceEnvelope } from "../src/governance-crypto.js";

function createMockKms() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  return {
    publicKeyPem,
    kmsPublicKey: async () => publicKeyPem,
    kmsSign: async (_keyVersion, data) => crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "der" }),
  };
}

const FAKE_KEY_VERSION = "projects/test/locations/us-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";

test("KMS-backed key material declares ECDSA_P256_SHA256 as its signature algorithm", async () => {
  // Regression test: the KMS-backed signer previously omitted
  // signatureAlgorithm, so signGovernancePayload defaulted the envelope's
  // signature.alg to "Ed25519" even though the bytes were DER-encoded
  // ECDSA P-256. Node's crypto.verify(null, ...) auto-routes by key type
  // so the broker still verified internally, but the external Go
  // verifier rejected the cert with "signature must be Ed25519".
  const { kmsSign, kmsPublicKey } = createMockKms();
  const keyMaterial = await createKmsBackedGovernanceKeyMaterial({
    keyVersionResource: FAKE_KEY_VERSION,
    kmsSign,
    kmsPublicKey,
  });
  assert.equal(keyMaterial.signatureAlgorithm, "ECDSA_P256_SHA256");
  assert.equal(keyMaterial.kind, "kms-backed");
});

test("signGovernancePayload labels KMS-signed envelopes as ECDSA_P256_SHA256 and they verify", async () => {
  const { kmsSign, kmsPublicKey, publicKeyPem } = createMockKms();
  const keyMaterial = await createKmsBackedGovernanceKeyMaterial({
    keyVersionResource: FAKE_KEY_VERSION,
    kmsSign,
    kmsPublicKey,
  });
  const envelope = await signGovernancePayload({ schema: "test.payload.v1", hello: "world" }, keyMaterial);
  assert.equal(envelope.signature.alg, "ECDSA_P256_SHA256");
  assert.equal(envelope.signingKeyId, keyMaterial.governanceKeyId);
  // Should verify cleanly under the correct algorithm label.
  const payload = verifyGovernanceEnvelope(envelope, publicKeyPem);
  assert.equal(payload.hello, "world");
});

test("legacy KMS-signed envelopes mis-labelled as Ed25519 still verify (auto-route by key type)", async () => {
  // Mirrors the behaviour the broker relies on across the rollout: even
  // if a previously-signed envelope carries the old Ed25519 label on an
  // EC key, verifyGovernanceEnvelope uses crypto.verify(null, ...) which
  // auto-routes to ECDSA based on the key type. This test pins that the
  // legacy lineage tail in production keeps verifying through the
  // transition.
  const { kmsSign, kmsPublicKey, publicKeyPem } = createMockKms();
  const keyMaterial = await createKmsBackedGovernanceKeyMaterial({
    keyVersionResource: FAKE_KEY_VERSION,
    kmsSign,
    kmsPublicKey,
  });
  const envelope = await signGovernancePayload({ schema: "test.payload.v1", legacy: true }, keyMaterial);
  // Force the legacy label that the previous broker emitted.
  envelope.signature.alg = "Ed25519";
  const payload = verifyGovernanceEnvelope(envelope, publicKeyPem);
  assert.equal(payload.legacy, true);
});

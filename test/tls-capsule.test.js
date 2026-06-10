import assert from "node:assert/strict";
import { test, beforeEach, afterEach } from "node:test";
import {
  sealTlsMaterial,
  unsealTlsMaterial,
  setTlsCapsuleTransportForTests,
  resetTlsCapsuleStatusForTests,
  getTlsCapsuleStatus,
  getTlsCapsuleLocation,
  TLS_CAPSULE_SCHEMA,
} from "../src/tls-capsule.js";

// Fake transport: an in-memory object store plus a reversible "KMS wrap" that
// prefixes the DEK, standing in for the attestation-gated ENCRYPT_DECRYPT key.
const WRAP_PREFIX = Buffer.from("kms-wrapped:");

function makeFakeTransport() {
  const store = new Map();
  return {
    store,
    transport: {
      kmsEncrypt: async (_keyName, plaintext) => Buffer.concat([WRAP_PREFIX, plaintext]),
      kmsDecrypt: async (_keyName, ciphertext) => {
        assert.ok(ciphertext.subarray(0, WRAP_PREFIX.length).equals(WRAP_PREFIX), "unwrap of non-wrapped DEK");
        return ciphertext.subarray(WRAP_PREFIX.length);
      },
      readObject: async (bucket, objectName) => store.get(`${bucket}/${objectName}`) ?? null,
      writeObject: async (bucket, objectName, value) => {
        store.set(`${bucket}/${objectName}`, JSON.parse(JSON.stringify(value)));
      },
    },
  };
}

// keyPem is opaque to the capsule (sealed as-is); a marker string keeps real
// private-key PEM markers out of the repo while still proving the plaintext
// never lands in the stored capsule.
const MATERIAL = {
  keyPem: "TEST-PRIVATE-KEY-MARKER-d41d8cd98f",
  certPem: "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n",
  mintedAt: "2026-06-10T00:00:00.000Z",
};

let fake;

function storedCapsule() {
  const { bucket, object } = getTlsCapsuleLocation();
  return fake.store.get(`${bucket}/${object}`) ?? null;
}

function setStoredCapsule(value) {
  const { bucket, object } = getTlsCapsuleLocation();
  fake.store.set(`${bucket}/${object}`, value);
}

beforeEach(() => {
  fake = makeFakeTransport();
  setTlsCapsuleTransportForTests(fake.transport);
  resetTlsCapsuleStatusForTests();
});

afterEach(() => {
  setTlsCapsuleTransportForTests(null);
  resetTlsCapsuleStatusForTests();
});

test("seal/unseal roundtrip preserves the material and the lineage anchor", async () => {
  await sealTlsMaterial({ ...MATERIAL, lineageId: "sha256:" + "a".repeat(64) });
  const unsealed = await unsealTlsMaterial();
  assert.equal(unsealed.keyPem, MATERIAL.keyPem);
  assert.equal(unsealed.certPem, MATERIAL.certPem);
  assert.equal(unsealed.mintedAt, MATERIAL.mintedAt);
  assert.equal(unsealed.lineageId, "sha256:" + "a".repeat(64));
  assert.ok(getTlsCapsuleStatus().lastSealAt);
  assert.equal(getTlsCapsuleStatus().lastSealError, null);
});

test("unseal returns null when no capsule exists yet (first genesis boot)", async () => {
  assert.equal(await unsealTlsMaterial(), null);
});

test("the stored capsule never contains plaintext key material and lives in the governance capsule bucket", async () => {
  await sealTlsMaterial({ ...MATERIAL, lineageId: null });
  const stored = storedCapsule();
  assert.ok(stored, "capsule must be stored at the documented bucket/object");
  assert.equal(stored.schema, TLS_CAPSULE_SCHEMA);
  const dump = JSON.stringify(stored);
  assert.ok(!dump.includes(MATERIAL.keyPem), "plaintext key leaked into the capsule");
  assert.ok(!dump.includes("test-cert"), "plaintext cert payload leaked into the capsule");
  for (const field of ["wrappedDek", "iv", "ciphertext", "authTag"]) {
    assert.equal(typeof stored[field], "string");
    assert.ok(stored[field].length > 0);
  }
  assert.match(getTlsCapsuleLocation().object, /^tls\/oauth-tee\.tls-capsule\.v1\.json$/);
});

test("tampering with the capsule's claimed lineageId fails the AAD-bound decrypt", async () => {
  await sealTlsMaterial({ ...MATERIAL, lineageId: "sha256:" + "a".repeat(64) });
  const stored = storedCapsule();
  // A new genesis can never silently consume an old lineage's capsule by
  // rewriting the cleartext anchor: GCM authenticates it as AAD.
  stored.lineageId = "sha256:" + "b".repeat(64);
  setStoredCapsule(stored);
  await assert.rejects(unsealTlsMaterial(), /Unsupported state or unable to authenticate data/);
});

test("tampering with the ciphertext fails the decrypt", async () => {
  await sealTlsMaterial({ ...MATERIAL, lineageId: null });
  const stored = storedCapsule();
  const bytes = Buffer.from(stored.ciphertext, "base64");
  bytes[0] ^= 0xff;
  stored.ciphertext = bytes.toString("base64");
  setStoredCapsule(stored);
  await assert.rejects(unsealTlsMaterial());
});

test("a capsule for a different service/host is rejected before any decrypt", async () => {
  await sealTlsMaterial({ ...MATERIAL, lineageId: null });
  const stored = storedCapsule();
  stored.host = "some-other-host.femled.ai";
  setStoredCapsule(stored);
  await assert.rejects(unsealTlsMaterial(), /service\/host mismatch/);
});

test("a seal failure is recorded for /health and rethrown", async () => {
  setTlsCapsuleTransportForTests({
    ...fake.transport,
    writeObject: async () => { throw new Error("gcs unavailable"); },
  });
  await assert.rejects(sealTlsMaterial({ ...MATERIAL, lineageId: null }), /gcs unavailable/);
  assert.match(getTlsCapsuleStatus().lastSealError.error, /gcs unavailable/);
});

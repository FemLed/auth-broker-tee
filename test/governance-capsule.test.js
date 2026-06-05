import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  STATE_CAPSULE_SCHEMA,
  STATE_CAPSULE_AAD_SCHEMA,
  buildStateCapsuleAad,
  createEncryptedStateCapsule,
  decryptStateCapsule,
  verifyWitnessSignature,
} from "../src/state-capsule.js";
import { canonicalStringify, sha256Digest } from "../src/canonical-json.js";

function createTestKmsBundle() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const kmsSign = async (buffer) => crypto.sign("sha256", buffer, { key: privateKey, dsaEncoding: "der" });
  return { publicKeyPem, kmsSign };
}

function digestOf(value) {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function sampleAad(overrides = {}) {
  return buildStateCapsuleAad({
    imageDigest: digestOf("running-image"),
    imageReference: "us-west1-docker.pkg.dev/test-project/auth-broker/auth-broker-tee",
    governanceKmsKeyVersion: "projects/test-project/locations/us-west1/keyRings/auth-broker-governance/cryptoKeys/governance-signer/cryptoKeyVersions/1",
    governancePublicKeyDigest: digestOf("kms-pubkey"),
    lineageDigest: digestOf("lineage"),
    epoch: 1,
    transferredStateDigest: digestOf("transferred"),
    status: "active",
    gcpProjectId: "test-project",
    capsuleSerial: 1,
    ...overrides,
  });
}

function samplePersistableState(overrides = {}) {
  return {
    schema: "femled.auth_broker_tee.governance.persistable_state.v1",
    status: "active",
    epoch: 1,
    imageDigest: digestOf("running-image"),
    governanceKeyId: digestOf("kms-pubkey"),
    governancePublicKeyPem: "-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n",
    governanceKmsKeyVersion: "projects/test-project/locations/us-west1/keyRings/auth-broker-governance/cryptoKeys/governance-signer/cryptoKeyVersions/1",
    lineage: [{ schema: "femled.tee.governance.envelope.v1", payload: { schema: "test", epoch: 1 } }],
    latestPreapproval: null,
    latestSuccessorCertificate: null,
    latestRetirementCertificate: null,
    transferredState: {
      schema: "femled.tee.governance.transferred_state.v1",
      routePolicy: { admittedTenants: {}, revocations: [] },
    },
    ...overrides,
  };
}

test("buildStateCapsuleAad enforces sha256 format and required fields", () => {
  assert.throws(
    () => buildStateCapsuleAad({}),
    /must be a sha256 digest/,
  );
  assert.throws(
    () => buildStateCapsuleAad({
      imageDigest: "not-a-digest",
      governancePublicKeyDigest: digestOf("x"),
      lineageDigest: digestOf("x"),
      transferredStateDigest: digestOf("x"),
      imageReference: "ref",
      governanceKmsKeyVersion: "projects/x/locations/y/keyRings/z/cryptoKeys/k/cryptoKeyVersions/1",
      epoch: 1,
      status: "active",
      gcpProjectId: "p",
      capsuleSerial: 1,
    }),
    /imageDigest must be a sha256 digest/,
  );
  assert.throws(
    () => buildStateCapsuleAad({
      imageDigest: digestOf("x"),
      governancePublicKeyDigest: digestOf("x"),
      lineageDigest: digestOf("x"),
      transferredStateDigest: digestOf("x"),
      imageReference: "ref",
      governanceKmsKeyVersion: "not-a-key-version",
      epoch: 1,
      status: "active",
      gcpProjectId: "p",
      capsuleSerial: 1,
    }),
    /Cloud KMS keyVersion/,
  );
  assert.throws(
    () => buildStateCapsuleAad({
      imageDigest: digestOf("x"),
      governancePublicKeyDigest: digestOf("x"),
      lineageDigest: digestOf("x"),
      transferredStateDigest: digestOf("x"),
      imageReference: "ref",
      governanceKmsKeyVersion: "projects/x/locations/y/keyRings/z/cryptoKeys/k/cryptoKeyVersions/1",
      epoch: 1,
      status: "not-a-status",
      gcpProjectId: "p",
      capsuleSerial: 1,
    }),
    /status must be a valid governance status/,
  );

  const aad = sampleAad();
  assert.equal(aad.schema, STATE_CAPSULE_AAD_SCHEMA);
  assert.equal(aad.status, "active");
});

test("capsule round-trip seals and unseals persistable state with matching AAD", async () => {
  const { publicKeyPem, kmsSign } = createTestKmsBundle();
  const aad = sampleAad();
  const persistableState = samplePersistableState();
  const capsule = await createEncryptedStateCapsule({
    persistableState,
    aad,
    kmsSign,
    kmsPublicKeyPem: publicKeyPem,
  });
  assert.equal(capsule.schema, STATE_CAPSULE_SCHEMA);
  assert.equal(capsule.aadDigest, sha256Digest(canonicalStringify(aad)));
  assert.match(capsule.capsuleDigest, /^sha256:[a-f0-9]{64}$/);

  const restored = decryptStateCapsule({
    capsule,
    expectedAad: aad,
    kmsPublicKeyPem: publicKeyPem,
  });
  assert.deepEqual(restored, persistableState);
});

test("capsule decrypt rejects AAD mismatch from different image digest", async () => {
  const { publicKeyPem, kmsSign } = createTestKmsBundle();
  const aad = sampleAad();
  const capsule = await createEncryptedStateCapsule({
    persistableState: samplePersistableState(),
    aad,
    kmsSign,
    kmsPublicKeyPem: publicKeyPem,
  });
  const tamperedAad = sampleAad({ imageDigest: digestOf("different-image") });
  assert.throws(
    () => decryptStateCapsule({
      capsule,
      expectedAad: tamperedAad,
      kmsPublicKeyPem: publicKeyPem,
    }),
    /capsule AAD does not match expected AAD/,
  );
});

test("capsule decrypt rejects a foreign KMS public key", async () => {
  const { publicKeyPem, kmsSign } = createTestKmsBundle();
  const { publicKeyPem: otherPublicKeyPem } = createTestKmsBundle();
  const aad = sampleAad();
  const capsule = await createEncryptedStateCapsule({
    persistableState: samplePersistableState(),
    aad,
    kmsSign,
    kmsPublicKeyPem: publicKeyPem,
  });
  assert.throws(
    () => decryptStateCapsule({
      capsule,
      expectedAad: aad,
      kmsPublicKeyPem: otherPublicKeyPem,
    }),
    /witness signature is invalid/,
  );
});

test("capsule rejects ciphertext tampering via AES-GCM auth tag", async () => {
  const { publicKeyPem, kmsSign } = createTestKmsBundle();
  const aad = sampleAad();
  const capsule = await createEncryptedStateCapsule({
    persistableState: samplePersistableState(),
    aad,
    kmsSign,
    kmsPublicKeyPem: publicKeyPem,
  });
  const flipped = Buffer.from(capsule.ciphertext, "base64url");
  flipped[0] ^= 0x01;
  const tamperedCapsule = { ...capsule, ciphertext: flipped.toString("base64url") };
  assert.throws(
    () => decryptStateCapsule({
      capsule: tamperedCapsule,
      expectedAad: aad,
      kmsPublicKeyPem: publicKeyPem,
    }),
  );
});

test("capsule rejects AAD field mutation in the capsule itself", async () => {
  const { publicKeyPem, kmsSign } = createTestKmsBundle();
  const aad = sampleAad();
  const capsule = await createEncryptedStateCapsule({
    persistableState: samplePersistableState(),
    aad,
    kmsSign,
    kmsPublicKeyPem: publicKeyPem,
  });
  // Mutate the AAD field embedded in the capsule. Both the recomputed AAD
  // digest and the AES-GCM AAD bytes will then fail to match.
  const mutatedCapsule = {
    ...capsule,
    aad: { ...capsule.aad, epoch: 999 },
  };
  assert.throws(
    () => decryptStateCapsule({
      capsule: mutatedCapsule,
      expectedAad: aad,
      kmsPublicKeyPem: publicKeyPem,
    }),
    /capsule aadDigest mismatch/,
  );
});

test("verifyWitnessSignature validates a signature produced by the KMS sign helper", async () => {
  const { publicKeyPem, kmsSign } = createTestKmsBundle();
  const aad = sampleAad();
  const aadBytes = Buffer.from(canonicalStringify(aad), "utf8");
  const signature = await kmsSign(aadBytes);
  assert.equal(verifyWitnessSignature({ aadBytes, witnessSignature: signature, kmsPublicKeyPem: publicKeyPem }), true);
  const flipped = Buffer.from(aadBytes);
  flipped[5] ^= 0x40;
  assert.equal(verifyWitnessSignature({ aadBytes: flipped, witnessSignature: signature, kmsPublicKeyPem: publicKeyPem }), false);
});

test("createEncryptedStateCapsule refuses to write a capsule when KMS self-verification fails", async () => {
  const { publicKeyPem } = createTestKmsBundle();
  const { kmsSign: foreignSign } = createTestKmsBundle();
  await assert.rejects(
    () => createEncryptedStateCapsule({
      persistableState: samplePersistableState(),
      aad: sampleAad(),
      kmsSign: foreignSign,
      kmsPublicKeyPem: publicKeyPem,
    }),
    /witness signature failed self-verification/,
  );
});

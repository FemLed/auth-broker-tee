// End-to-end test for the governance state capsule restore path.
//
// Simulates the cold-start sequence on a fresh VM with the same image
// digest as the previously-active TEE: a KMS-backed governance key, a
// capsule + latest-pointer in a stub "GCS" bucket. Confirms restore lands
// `state.status === active` with the same lineage, epoch, and route policy.
//
// This test injects mocks for KMS and GCS rather than calling the real
// modules, so it is fully hermetic. Production wiring goes through
// `src/capsule-store.js` (real GCS) and `src/kms-governance-key.js`
// (real Cloud KMS asymmetricSign).

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  resetGovernanceForTests,
  getGovernanceState,
  initializeGovernance,
  initializeGovernanceAsync,
  buildPersistableState,
  persistGovernanceCapsule,
  tryRestoreGovernanceFromCapsule,
  retryGovernanceRestoreIfDegraded,
  bootstrapGenesisFromAttestedApproval,
  completeActivation,
  applyActivationBundle,
} from "../src/governance-state.js";
import {
  signGenesisCertificate,
  signSuccessorCertificate,
} from "../src/governance-certificates.js";
import { resetGovernanceMonitorForTests } from "../src/governance-monitor.js";
import {
  buildLatestPointer,
} from "../src/capsule-store.js";
import { resetRepairJobsForTests } from "../src/governance-repair-jobs.js";
import { primeWifTokenForTests } from "../src/gcp-auth.js";
import { canonicalStringify } from "../src/canonical-json.js";

// In-memory "GCS bucket" backing store. We monkey-patch
// `fetch` to intercept the few REST calls the capsule store + WIF helper make.
function installInMemoryGcsBucket() {
  const store = new Map();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const parsed = new URL(url);
    if (parsed.hostname === "sts.googleapis.com") {
      return new Response(
        JSON.stringify({ access_token: "fake-wif-token", expires_in: 3600 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    if (parsed.hostname === "storage.googleapis.com" && parsed.pathname.startsWith("/upload/storage/v1/b/")) {
      const objectName = parsed.searchParams.get("name");
      store.set(objectName, init.body);
      return new Response(JSON.stringify({ name: objectName }), { status: 200 });
    }
    if (parsed.hostname === "storage.googleapis.com" && parsed.pathname.startsWith("/storage/v1/b/")) {
      const pathParts = parsed.pathname.split("/o/");
      if (pathParts.length === 2) {
        const objectName = decodeURIComponent(pathParts[1]);
        if (!store.has(objectName)) {
          return new Response("Not Found", { status: 404 });
        }
        return new Response(store.get(objectName), { status: 200 });
      }
    }
    if (originalFetch) return originalFetch(url, init);
    return new Response("Not Found", { status: 404 });
  };
  return {
    store,
    restore() {
      globalThis.fetch = originalFetch;
    },
  };
}

function createMockKmsBackedKeyMaterial({ keyVersion } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const governancePublicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const publicKeyDer = crypto.createPublicKey(governancePublicKeyPem).export({ type: "spki", format: "der" });
  const governanceKeyId = `sha256:${crypto.createHash("sha256").update(publicKeyDer).digest("hex")}`;
  const activation = crypto.generateKeyPairSync("x25519");
  const activationPublicKeyPem = activation.publicKey.export({ type: "spki", format: "pem" });
  const activationPubKeyDer = crypto.createPublicKey(activationPublicKeyPem).export({ type: "spki", format: "der" });
  const activationKeyId = `sha256:${crypto.createHash("sha256").update(activationPubKeyDer).digest("hex")}`;

  return Object.freeze({
    kind: "kms-backed",
    signatureAlgorithm: "ECDSA_P256_SHA256",
    kmsKeyVersion: keyVersion || "projects/test-project/locations/us-west1/keyRings/auth-broker-governance/cryptoKeys/governance-signer/cryptoKeyVersions/1",
    governancePublicKeyPem,
    governanceKeyId,
    activationPublicKeyPem,
    activationKeyId,
    async sign(payload) {
      const canonical = Buffer.from(canonicalStringify(payload), "utf8");
      return crypto.sign("sha256", canonical, { key: privateKey, dsaEncoding: "der" }).toString("base64url");
    },
    async signWithKms(buffer) {
      return crypto.sign("sha256", buffer, { key: privateKey, dsaEncoding: "der" });
    },
    async getKmsPublicKeyPem() {
      return governancePublicKeyPem;
    },
    decryptState() {
      throw new Error("activation decryption is out of scope for capsule restore tests");
    },
    encryptStateFor() {
      throw new Error("activation encryption is out of scope for capsule restore tests");
    },
  });
}

function withCapsuleEnv(fn) {
  return async (t) => {
    const prevBucket = process.env.CAPSULE_BUCKET;
    const prevKey = process.env.GOVERNANCE_KMS_SIGNER_KEY_VERSION;
    const prevProject = process.env.GCP_PROJECT_ID;
    const prevImage = process.env.TEE_LOCAL_IMAGE_DIGEST;
    const prevImageRef = process.env.TEE_LOCAL_IMAGE_REFERENCE;
    process.env.CAPSULE_BUCKET = "test-bucket";
    process.env.GOVERNANCE_KMS_SIGNER_KEY_VERSION = "projects/test-project/locations/us-west1/keyRings/auth-broker-governance/cryptoKeys/governance-signer/cryptoKeyVersions/1";
    process.env.GCP_PROJECT_ID = "test-project";
    process.env.TEE_LOCAL_IMAGE_DIGEST = "sha256:" + "ab".repeat(32);
    process.env.TEE_LOCAL_IMAGE_REFERENCE = "us-west1-docker.pkg.dev/test-project/auth-broker/auth-broker-tee";
    const bucket = installInMemoryGcsBucket();
    primeWifTokenForTests("fake-wif-token");
    try {
      await fn(t, bucket);
    } finally {
      primeWifTokenForTests(null);
      bucket.restore();
      if (prevBucket === undefined) delete process.env.CAPSULE_BUCKET; else process.env.CAPSULE_BUCKET = prevBucket;
      if (prevKey === undefined) delete process.env.GOVERNANCE_KMS_SIGNER_KEY_VERSION; else process.env.GOVERNANCE_KMS_SIGNER_KEY_VERSION = prevKey;
      if (prevProject === undefined) delete process.env.GCP_PROJECT_ID; else process.env.GCP_PROJECT_ID = prevProject;
      if (prevImage === undefined) delete process.env.TEE_LOCAL_IMAGE_DIGEST; else process.env.TEE_LOCAL_IMAGE_DIGEST = prevImage;
      if (prevImageRef === undefined) delete process.env.TEE_LOCAL_IMAGE_REFERENCE; else process.env.TEE_LOCAL_IMAGE_REFERENCE = prevImageRef;
    }
  };
}

test("persist and restore: capsule restore lands ACTIVE with same lineage and route policy", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  // Phase 1: simulate steady-state ACTIVE TEE with KMS key + capsule write.
  const keyMaterial = createMockKmsBackedKeyMaterial();
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial });
  // Manually mark the running image digest on state to match env override
  // (genesis init reads readCurrentImageDigest which falls back to env when
  // launcher attestation is unavailable in test mode).
  const stateBefore = getGovernanceState();
  assert.equal(stateBefore.status, "active");
  assert.equal(stateBefore.keyMaterial.kind, "kms-backed");

  const persisted = await persistGovernanceCapsule();
  assert.match(persisted.capsuleDigest, /^sha256:[a-f0-9]{64}$/);

  // Snapshot the lineage and route policy we expect to recover.
  const lineageDigestBefore = JSON.stringify(stateBefore.lineage);
  const transferredBefore = JSON.stringify(stateBefore.transferredState);
  const epochBefore = stateBefore.epoch;
  const governanceKeyIdBefore = stateBefore.keyMaterial.governanceKeyId;

  // Phase 2: simulate cold start. Reset the in-memory state, but keep the
  // same key material (because in production the same image digest under
  // KMS WIF still mints the same governance public key on the new VM).
  resetGovernanceForTests(null);
  await initializeGovernanceAsync({ mode: "inactive", keyMaterial });
  const inactive = getGovernanceState();
  // initializeGovernanceAsync will auto-attempt restore when KMS+CAPSULE
  // are configured; verify it landed active.
  if (inactive.status === "inactive") {
    // Manual restore for assertion clarity.
    var restored = await tryRestoreGovernanceFromCapsule();
  } else {
    var restored = { status: inactive.status, epoch: inactive.epoch };
  }
  assert.ok(restored, "tryRestoreGovernanceFromCapsule should return restore evidence");
  assert.equal(restored.status, "active");
  assert.equal(restored.epoch, epochBefore);

  const stateAfter = getGovernanceState();
  assert.equal(stateAfter.status, "active");
  assert.equal(stateAfter.epoch, epochBefore);
  assert.equal(JSON.stringify(stateAfter.lineage), lineageDigestBefore);
  assert.equal(JSON.stringify(stateAfter.transferredState), transferredBefore);
  assert.equal(stateAfter.keyMaterial.governanceKeyId, governanceKeyIdBefore);
}));

test("persist and restore: capsule with mismatched image digest is refused", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const keyMaterial = createMockKmsBackedKeyMaterial();
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial });

  // Phase 2: change the running image digest, simulating a new image roll.
  // Capsule was sealed for the previous imageDigest and must be rejected.
  process.env.TEE_LOCAL_IMAGE_DIGEST = "sha256:" + "cd".repeat(32);
  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial });

  const restored = await tryRestoreGovernanceFromCapsule();
  assert.equal(restored, null, "capsule restore must refuse to restore when imageDigest does not match running");
  const after = getGovernanceState();
  assert.equal(after.status, "inactive");
}));

test("persist and restore: capsule with mismatched KMS key version is refused", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const km1 = createMockKmsBackedKeyMaterial();
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial: km1 });

  // Phase 2: cold start with a different KMS key version (and therefore a
  // different governance public key). The pointer's governanceKmsKeyVersion
  // must match the live key material, and the lineage's ACTIVE governance key
  // must match the KMS-bound governanceKeyId. Both fail here.
  const km2 = createMockKmsBackedKeyMaterial({
    keyVersion: "projects/test-project/locations/us-west1/keyRings/auth-broker-governance/cryptoKeys/governance-signer/cryptoKeyVersions/2",
  });
  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial: km2 });

  const restored = await tryRestoreGovernanceFromCapsule();
  assert.equal(restored, null, "capsule restore must refuse to restore under a different KMS key version");
  const after = getGovernanceState();
  assert.equal(after.status, "inactive");
}));

test("buildPersistableState exposes only the recoverable subset", () => {
  resetGovernanceForTests(null);
  resetGovernanceMonitorForTests();
  initializeGovernance({ mode: "genesis" });
  const persistable = buildPersistableState();
  // Forbidden fields: anything that contains a private key or transient HTTP
  // state. We check the schema explicitly and that none of the JSON contains
  // the strings "privateKey", "Map", or "pendingActivationChallenges".
  assert.equal(persistable.schema, "femled.auth_broker_tee.governance.persistable_state.v1");
  const serialized = JSON.stringify(persistable);
  assert.equal(serialized.includes("privateKey"), false);
  assert.equal(serialized.includes("pendingActivationChallenges"), false);
  assert.equal(serialized.includes("selfHealingProposals"), false);
});

test("buildLatestPointer enforces field types", () => {
  assert.throws(
    () => buildLatestPointer({ capsuleDigest: "not-a-digest", imageDigest: "sha256:" + "0".repeat(64), governanceKmsKeyVersion: "v", epoch: 1, status: "active", capsuleSerial: 1, lineageDigest: "sha256:" + "0".repeat(64) }),
    /capsuleDigest must be a sha256 digest/,
  );
  assert.throws(
    () => buildLatestPointer({ capsuleDigest: "sha256:" + "0".repeat(64), imageDigest: "not-a-digest", governanceKmsKeyVersion: "v", epoch: 1, status: "active", capsuleSerial: 1, lineageDigest: "sha256:" + "0".repeat(64) }),
    /imageDigest must be a sha256 digest/,
  );
  const pointer = buildLatestPointer({
    capsuleDigest: "sha256:" + "1".repeat(64),
    imageDigest: "sha256:" + "2".repeat(64),
    governanceKmsKeyVersion: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    epoch: 1,
    status: "active",
    capsuleSerial: 1,
    lineageDigest: "sha256:" + "3".repeat(64),
  });
  assert.equal(pointer.schema, "femled.auth_broker_tee.governance_state_capsule.latest_pointer.v1");
});

// ---------------------------------------------------------------------------
// Successor-activated lineage restore (regression for the inactive-broker
// incident). A successor certificate is signed by the PREDECESSOR and only
// NAMES the new active key, so the lineage TAIL's signingKeyId is never the
// current key once the broker has activated past genesis. The restore gate
// must therefore check the lineage's ACTIVE key, not the tail signer.
// ---------------------------------------------------------------------------

const DUMMY_DIGEST = "sha256:" + "11".repeat(32);
const kmsKeyVersion = (n) =>
  `projects/test-project/locations/us-west1/keyRings/auth-broker-governance/cryptoKeys/governance-signer/cryptoKeyVersions/${n}`;

// Build a 2-epoch lineage: genesis (epoch 1, self-signed by predecessorKey)
// followed by a successor cert (epoch 2) that the PREDECESSOR signs to hand off
// to successorKey. verifyLineage's active key is then successorKey's public key.
async function buildSuccessorLineage({ predecessorKey, successorKey, imageDigest, now }) {
  const genesis = await signGenesisCertificate({
    keyMaterial: predecessorKey,
    imageDigest,
    routeRegistryStatus: { trustAnchorsDigest: null, routeBundleDigest: null },
    attestationDigest: null,
    now,
  });
  const successor = await signSuccessorCertificate({
    keyMaterial: predecessorKey, // predecessor signs the successor certificate
    predecessorEpoch: 1,
    successorEpoch: 2,
    candidateImageDigest: imageDigest,
    candidateAttestationDigest: DUMMY_DIGEST,
    candidateAttestationNonce: "successor-activation-nonce",
    preapprovalPayloadDigest: DUMMY_DIGEST,
    successorDecisionPacketDigest: DUMMY_DIGEST,
    successorArbitrationDigest: DUMMY_DIGEST,
    successorGovernancePublicKeyPem: successorKey.governancePublicKeyPem,
    successorGovernanceKeyId: successorKey.governanceKeyId,
    successorActivationPublicKeyPem: successorKey.activationPublicKeyPem,
    now,
  });
  return [genesis, successor];
}

test("persist and restore: successor-activated lineage restores ACTIVE (predecessor-signed tail, active key == KMS key)", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const now = new Date();
  const imageDigest = process.env.TEE_LOCAL_IMAGE_DIGEST;
  // predecessorKey = epoch-1 (genesis) key that later signs the handoff.
  // kmsKey = epoch-2 active key the cold-started VM mints from the SAME KMS
  // key version (kmsKeyVersion 1 == GOVERNANCE_KMS_SIGNER_KEY_VERSION).
  const predecessorKey = createMockKmsBackedKeyMaterial({ keyVersion: kmsKeyVersion(9) });
  const kmsKey = createMockKmsBackedKeyMaterial();

  const lineage = await buildSuccessorLineage({ predecessorKey, successorKey: kmsKey, imageDigest, now });

  // Seal an ACTIVE epoch-2 capsule whose live key material is the KMS key but
  // whose lineage tail is predecessor-signed.
  initializeGovernance({ mode: "inactive", keyMaterial: kmsKey });
  const live = getGovernanceState();
  live.status = "active";
  live.epoch = 2;
  live.lineage = lineage;
  const persisted = await persistGovernanceCapsule({ now });
  assert.match(persisted.capsuleDigest, /^sha256:[a-f0-9]{64}$/);

  // Cold start with the same KMS key, empty lineage, inactive.
  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial: kmsKey });
  const restored = await tryRestoreGovernanceFromCapsule({ now });

  assert.ok(restored, "successor-activated capsule must restore (regression: the tail-signer gate refused it and forced re-genesis)");
  assert.equal(restored.status, "active");
  assert.equal(restored.epoch, 2);
  const after = getGovernanceState();
  assert.equal(after.status, "active");
  assert.equal(after.epoch, 2);
  assert.equal(after.lineage.length, 2);
  assert.equal(after.keyMaterial.governanceKeyId, kmsKey.governanceKeyId);
}));

test("persist and restore: successor lineage whose active key != KMS key is refused", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const now = new Date();
  const imageDigest = process.env.TEE_LOCAL_IMAGE_DIGEST;
  const predecessorKey = createMockKmsBackedKeyMaterial({ keyVersion: kmsKeyVersion(9) });
  const kmsKey = createMockKmsBackedKeyMaterial();                                   // live cold-start key
  const foreignActiveKey = createMockKmsBackedKeyMaterial({ keyVersion: kmsKeyVersion(7) }); // lineage hands off here

  // Lineage hands off to foreignActiveKey, NOT the live KMS key.
  const lineage = await buildSuccessorLineage({ predecessorKey, successorKey: foreignActiveKey, imageDigest, now });

  // Seal so the pointer/persistable governance key == the live KMS key (so the
  // earlier public-key gate passes), while the lineage's ACTIVE key is foreign.
  // The active-key gate must refuse rather than restore a mismatched lineage.
  initializeGovernance({ mode: "inactive", keyMaterial: kmsKey });
  const live = getGovernanceState();
  live.status = "active";
  live.epoch = 2;
  live.lineage = lineage;
  await persistGovernanceCapsule({ now });

  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial: kmsKey });
  const restored = await tryRestoreGovernanceFromCapsule({ now });
  assert.equal(restored, null, "capsule whose lineage active key != KMS key must be refused");
  assert.equal(getGovernanceState().status, "inactive");
}));

test("production refuses to establish active governance with non-KMS key material", withCapsuleEnv(async () => {
  const prevEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";
  try {
    // applyActivationBundle: inactive candidate holding an in-memory key.
    resetGovernanceMonitorForTests();
    resetGovernanceForTests(null);
    initializeGovernance({ mode: "inactive" });
    await assert.rejects(
      () => applyActivationBundle({ successorCertificate: {}, encryptedState: {}, predecessorActivationPublicKeyPem: "x", activationNonce: "n" }),
      /non-KMS-backed key material in production/,
    );

    // bootstrapGenesisFromAttestedApproval: inactive, empty lineage, in-memory key.
    resetGovernanceForTests(null);
    initializeGovernance({ mode: "inactive" });
    await assert.rejects(
      () => bootstrapGenesisFromAttestedApproval({}),
      /non-KMS-backed key material in production/,
    );

    // completeActivation: active in-memory predecessor signing a successor.
    resetGovernanceForTests(null);
    initializeGovernance({ mode: "genesis" });
    await assert.rejects(
      () => completeActivation({}),
      /non-KMS-backed key material in production/,
    );
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
  }
}));

test("retry restores ACTIVE after a transient KMS failure at boot (fail closed, then self-heal)", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const now = new Date();
  const kmsKey = createMockKmsBackedKeyMaterial();

  // Phase 1: steady-state ACTIVE genesis sealed under the KMS key.
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial: kmsKey });
  assert.equal(getGovernanceState().status, "active");
  await persistGovernanceCapsule({ now });

  // Phase 2: cold start where KMS key init FAILS once. The broker must fail
  // closed (stay inactive, in-memory shell) -- NOT silently activate/restore.
  resetGovernanceForTests(null);
  let kmsCalls = 0;
  const flakyFactory = async () => {
    kmsCalls += 1;
    if (kmsCalls === 1) throw new Error("simulated transient KMS outage");
    return kmsKey;
  };
  await initializeGovernanceAsync({ mode: "inactive", createKeyMaterial: flakyFactory });
  assert.equal(getGovernanceState().status, "inactive", "must fail closed (inactive) when KMS init fails at boot");
  assert.equal(getGovernanceState().keyMaterial.kind, "in-memory");

  // Phase 3: retry on the refresh-loop cadence; KMS now succeeds -> restore.
  const restored = await retryGovernanceRestoreIfDegraded({ now, createKeyMaterial: flakyFactory });
  assert.ok(restored, "retry must restore once KMS recovers");
  assert.equal(restored.status, "active");
  assert.equal(getGovernanceState().status, "active");
  assert.equal(getGovernanceState().keyMaterial.kind, "kms-backed");
  assert.equal(kmsCalls, 2);

  // A second retry once active is a no-op.
  assert.equal(await retryGovernanceRestoreIfDegraded({ now, createKeyMaterial: flakyFactory }), null);
  assert.equal(kmsCalls, 2);
}));

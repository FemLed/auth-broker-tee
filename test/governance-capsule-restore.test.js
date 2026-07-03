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
  governanceCapsuleHeartbeatIfDue,
  getCapsuleSerial,
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
      // Object list endpoint: GET /storage/v1/b/<bucket>/o?prefix=capsules/
      if (parsed.pathname.endsWith("/o")) {
        const prefix = parsed.searchParams.get("prefix") || "";
        const items = [...store.keys()]
          .filter((name) => name.startsWith(prefix))
          .map((name) => ({ name }));
        return new Response(JSON.stringify({ items }), { status: 200 });
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

// ---------------------------------------------------------------------------
// Part A: capsule rollback floor. Restore enumerates the bucket and picks the
// highest AUTHENTIC (KMS-witness-signed) capsuleSerial, ignoring the mutable
// latest-pointer. Paired with the locked GCS retention policy (Terraform), an
// attacker cannot roll governance back to an older still-present capsule.
// ---------------------------------------------------------------------------

test("rollback floor: restore picks the highest authentic capsule serial among many", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const keyMaterial = createMockKmsBackedKeyMaterial();
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial }); // serial 1
  const p2 = await persistGovernanceCapsule(); // serial 2
  const p3 = await persistGovernanceCapsule(); // serial 3
  assert.equal(p2.capsuleSerial, 2);
  assert.equal(p3.capsuleSerial, 3);

  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial });
  const restored = await tryRestoreGovernanceFromCapsule();
  assert.ok(restored);
  assert.equal(restored.status, "active");
  assert.equal(restored.capsuleSerial, 3, "restore must land on the highest authentic serial");
  assert.equal(getCapsuleSerial(), 3);
}));

test("rollback floor: a rewound latest-pointer is ignored; restore still lands the true head", withCapsuleEnv(async (t, bucket) => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const keyMaterial = createMockKmsBackedKeyMaterial();
  const g = await initializeGovernanceAsync({ mode: "genesis", keyMaterial }); // serial 1
  void g;
  const p1Serial = getCapsuleSerial(); // 1
  const lineageDigest = sha256Of(getGovernanceState().lineage);
  const p1Digest = (await readPointerFromStore(bucket)).capsuleDigest; // capsule at serial 1
  await persistGovernanceCapsule(); // serial 2
  await persistGovernanceCapsule(); // serial 3

  // Attacker rewinds the mutable pointer to name the serial-1 capsule.
  bucket.store.set("capsules/latest-pointer.json", JSON.stringify(buildLatestPointer({
    capsuleDigest: p1Digest,
    imageDigest: process.env.TEE_LOCAL_IMAGE_DIGEST,
    governanceKmsKeyVersion: keyMaterial.kmsKeyVersion,
    epoch: 1,
    status: "active",
    capsuleSerial: p1Serial,
    lineageDigest,
  })));

  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial });
  const restored = await tryRestoreGovernanceFromCapsule();
  assert.ok(restored);
  assert.equal(restored.capsuleSerial, 3, "the rewound pointer must not roll governance back below the true head");
  assert.equal(getCapsuleSerial(), 3);
}));

test("rollback floor: forged/undecryptable capsule objects are skipped", withCapsuleEnv(async (t, bucket) => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const keyMaterial = createMockKmsBackedKeyMaterial();
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial }); // one authentic capsule, serial 1

  // Inject junk objects under capsules/ that must be skipped (they do not
  // decrypt under our KMS witness key). A well-formed capsule name so it is
  // listed, but a body that is not an authentic capsule.
  bucket.store.set(`capsules/${"cc".repeat(32)}.json`, JSON.stringify({ schema: "not-a-capsule" }));
  bucket.store.set(`capsules/${"dd".repeat(32)}.json`, "not even json");

  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial });
  const restored = await tryRestoreGovernanceFromCapsule();
  assert.ok(restored, "restore must succeed on the one authentic capsule and ignore the forgeries");
  assert.equal(restored.status, "active");
  assert.equal(restored.capsuleSerial, 1);
}));

test("rollback floor: re-genesis seeds its serial above an abandoned lineage (no rollback into it)", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const keyMaterial = createMockKmsBackedKeyMaterial();

  // Lineage L1: genesis + two more persists (serials 1..3), then abandoned.
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial, now: new Date("2026-01-01T00:00:00Z") });
  await persistGovernanceCapsule();
  await persistGovernanceCapsule();
  const l1GenesisDigest = getGovernanceState().lineage[0].payloadDigest;
  assert.equal(getCapsuleSerial(), 3);

  // Operator re-genesis on the SAME image + KMS key. The abandoned L1 capsules
  // remain in the (retention-locked) bucket at serials 1..3. The new genesis
  // must seed ABOVE them so highest-serial-wins can never resurrect L1.
  resetGovernanceForTests(null);
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial, now: new Date("2026-02-02T00:00:00Z") });
  const l2GenesisDigest = getGovernanceState().lineage[0].payloadDigest;
  assert.notEqual(l2GenesisDigest, l1GenesisDigest, "re-genesis must produce a distinct lineage");
  assert.equal(getCapsuleSerial(), 4, "re-genesis seeds its serial above the abandoned lineage's max (3) -> 4");

  // Cold boot: restore must land the NEW genesis (serial 4), not abandoned L1.
  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial });
  const restored = await tryRestoreGovernanceFromCapsule();
  assert.ok(restored);
  assert.equal(restored.capsuleSerial, 4);
  assert.equal(getGovernanceState().lineage[0].payloadDigest, l2GenesisDigest, "must restore the new genesis, never the abandoned lineage");
}));

test("heartbeat: re-seals a fresh higher-serial capsule when due, and is a no-op otherwise", withCapsuleEnv(async () => {
  resetGovernanceMonitorForTests();
  resetRepairJobsForTests();
  resetGovernanceForTests(null);

  const keyMaterial = createMockKmsBackedKeyMaterial();
  await initializeGovernanceAsync({ mode: "genesis", keyMaterial }); // serial 1, sets lastPersistAt
  assert.equal(getCapsuleSerial(), 1);

  // Not due yet (default 24h interval): no-op.
  assert.equal(await governanceCapsuleHeartbeatIfDue({ now: new Date() }), null);
  assert.equal(getCapsuleSerial(), 1);

  // Well past the interval: re-seals a fresh higher-serial head.
  const farFuture = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
  const beat = await governanceCapsuleHeartbeatIfDue({ now: farFuture });
  assert.ok(beat, "heartbeat must persist when the interval has elapsed");
  assert.equal(getCapsuleSerial(), 2);

  // Immediately after, it is a no-op again (lastPersistAt just advanced).
  assert.equal(await governanceCapsuleHeartbeatIfDue({ now: farFuture }), null);
  assert.equal(getCapsuleSerial(), 2);

  // Inactive governance never heartbeats.
  resetGovernanceForTests(null);
  initializeGovernance({ mode: "inactive", keyMaterial });
  assert.equal(await governanceCapsuleHeartbeatIfDue({ now: farFuture }), null);
}));

function sha256Of(value) {
  return `sha256:${crypto.createHash("sha256").update(canonicalStringify(value)).digest("hex")}`;
}

async function readPointerFromStore(bucket) {
  const raw = bucket.store.get("capsules/latest-pointer.json");
  return raw ? JSON.parse(raw) : null;
}

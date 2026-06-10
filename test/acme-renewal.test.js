import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test, beforeEach, afterEach } from "node:test";
import { adoptTlsMaterial, getCurrentTlsMaterial, resetTlsMaterialForTests, setTlsServer } from "../src/tls-material.js";
import { setTlsCapsuleTransportForTests, resetTlsCapsuleStatusForTests, getTlsCapsuleLocation } from "../src/tls-capsule.js";

// Keep the boot bootstrap fast under test: these are read at module load, so
// they must be set before the renewer module is imported (node --test runs
// each test file in its own process, so this dynamic import is the first and
// only evaluation of the module).
process.env.ACME_BOOTSTRAP_MAX_ATTEMPTS = "2";
process.env.ACME_BOOTSTRAP_RETRY_DELAY_MS = "1";
const {
  runOnce,
  bootstrapTls,
  renewIfDue,
  reconcileTlsWithLineage,
  setDnsTeeFetcherForTests,
  setRenewerEnvelopeBuilderForTests,
  setRenewerDriversForTests,
  resetTlsSupervisorForTests,
  getTlsRuntimeStatus,
} = await import("../src/acme-renewal.js");

// Self-signed PUBLIC cert fixtures for oauth-tee.femled.ai (no private-key
// PEMs are committed; nothing in the code under test parses the key, so
// opaque marker strings stand in for keys). Tests inject `now` instead of
// relying on wall-clock time, so the long lifetimes only anchor the relative
// "fresh / due / expired" timelines:
//   CERT_100Y expires 2126-05-17; CERT_200Y expires 2226-04-23.
const KEY_100Y = "in-memory-test-key-100y";
const CERT_100Y = `-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIUM9c1B+ODbKzv/Z8qI4DUSLQMWmIwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTb2F1dGgtdGVlLmZlbWxlZC5haTAgFw0yNjA2MTAxODM2MDZa
GA8yMTI2MDUxNzE4MzYwNlowHjEcMBoGA1UEAwwTb2F1dGgtdGVlLmZlbWxlZC5h
aTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFxurbyfuWZZrBJlkTS0eVrOrMUM
WZWFEHOGrFJwGv0cr/fiVirX87dneQDKkhWw+QWU+drJX/ZtGvJDHF/qNGejUzBR
MB0GA1UdDgQWBBTqP3Hq2nKND1l2i73ULKz17ZxB+DAfBgNVHSMEGDAWgBTqP3Hq
2nKND1l2i73ULKz17ZxB+DAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gA
MEUCIQD9K/x+H5H1QupKbeasrnh6w82ADAZPyz+nCFXHHc4lAwIgWiycJZ1NoYC+
kvLlyJOXlHqSDR6yFG9f8Kc/u8XIrXw=
-----END CERTIFICATE-----
`;
const KEY_200Y = "in-memory-test-key-200y";
const CERT_200Y = `-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIUHzgRWFk3bNjQ6ejsOgnE06ag2YcwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTb2F1dGgtdGVlLmZlbWxlZC5haTAgFw0yNjA2MTAxODM2MDZa
GA8yMjI2MDQyMzE4MzYwNlowHjEcMBoGA1UEAwwTb2F1dGgtdGVlLmZlbWxlZC5h
aTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOWs5q+nK/zl7roRC8i2CcPie+tQ
65WLG0E/5LlhirbpdiE6+yBNGDd7T0rZfX327N33MhkAkC0GVJg+q+cWhWGjUzBR
MB0GA1UdDgQWBBQGJ/FVGVYUbCblNI2hkMkOMEngJjAfBgNVHSMEGDAWgBQGJ/FV
GVYUbCblNI2hkMkOMEngJjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gA
MEUCIQDVTWgf21zCvG1Gs52UaNmjtgucG2USIHGX02VBIJeIpgIgbMHK2wvqSTUJ
iYSsvzn8oeeLtMuQJvUtmmWIt71vYg4=
-----END CERTIFICATE-----
`;

const TODAY = new Date("2026-06-11T00:00:00Z"); // both certs fresh
const DUE_100Y = new Date("2126-05-10T00:00:00Z"); // 100y cert inside 30d window, 200y cert fresh
const EXPIRED_100Y = new Date("2126-06-01T00:00:00Z"); // 100y cert expired

const ORIGINAL_ENV = {
  ACME_RENEWER_ENABLED: process.env.ACME_RENEWER_ENABLED,
  ACME_RENEWER_DRY_RUN: process.env.ACME_RENEWER_DRY_RUN,
  RENEWER_KMS_SIGNER_KEY_VERSION: process.env.RENEWER_KMS_SIGNER_KEY_VERSION,
  DNS_TEE_RENEWER_URLS: process.env.DNS_TEE_RENEWER_URLS,
};

const WRAP_PREFIX = Buffer.from("kms-wrapped:");
let capsuleStore;

function installFakeCapsuleTransport() {
  capsuleStore = new Map();
  setTlsCapsuleTransportForTests({
    kmsEncrypt: async (_keyName, plaintext) => Buffer.concat([WRAP_PREFIX, plaintext]),
    kmsDecrypt: async (_keyName, ciphertext) => ciphertext.subarray(WRAP_PREFIX.length),
    readObject: async (bucket, objectName) => capsuleStore.get(`${bucket}/${objectName}`) ?? null,
    writeObject: async (bucket, objectName, value) => {
      capsuleStore.set(`${bucket}/${objectName}`, JSON.parse(JSON.stringify(value)));
    },
  });
}

async function seedCapsule(material) {
  const { sealTlsMaterial } = await import("../src/tls-capsule.js");
  await sealTlsMaterial(material);
}

function storedCapsule() {
  const { bucket, object } = getTlsCapsuleLocation();
  return capsuleStore.get(`${bucket}/${object}`) ?? null;
}

function enableRenewer() {
  process.env.ACME_RENEWER_ENABLED = "true";
  process.env.ACME_RENEWER_DRY_RUN = "false";
  process.env.RENEWER_KMS_SIGNER_KEY_VERSION = "test-key";
}

beforeEach(() => {
  process.env.ACME_RENEWER_ENABLED = "false";
  process.env.ACME_RENEWER_DRY_RUN = "false";
  process.env.RENEWER_KMS_SIGNER_KEY_VERSION = "test-key";
  setDnsTeeFetcherForTests(null);
  setRenewerEnvelopeBuilderForTests(null);
  setRenewerDriversForTests(null);
  resetTlsMaterialForTests();
  resetTlsSupervisorForTests();
  resetTlsCapsuleStatusForTests();
  installFakeCapsuleTransport();
});

afterEach(() => {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  setDnsTeeFetcherForTests(null);
  setRenewerEnvelopeBuilderForTests(null);
  setRenewerDriversForTests(null);
  resetTlsMaterialForTests();
  resetTlsSupervisorForTests();
  resetTlsCapsuleStatusForTests();
  setTlsCapsuleTransportForTests(null);
});

test("renewIfDue returns skipped when ACME_RENEWER_ENABLED is false", async () => {
  process.env.ACME_RENEWER_ENABLED = "false";
  const result = await renewIfDue();
  assert.equal(result.status, "skipped");
  assert.match(result.reason, /ACME_RENEWER_ENABLED is false/);
});

test("renewIfDue returns skipped when RENEWER_KMS_SIGNER_KEY_VERSION is missing", async () => {
  process.env.ACME_RENEWER_ENABLED = "true";
  delete process.env.RENEWER_KMS_SIGNER_KEY_VERSION;
  const result = await renewIfDue();
  assert.equal(result.status, "skipped");
  assert.match(result.reason, /RENEWER_KMS_SIGNER_KEY_VERSION/);
});

test("renewIfDue reads the renewal window from the IN-MEMORY cert (no Secret Manager)", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y }, { origin: "minted_in_enclave" });
  const result = await renewIfDue({ now: TODAY });
  assert.equal(result.status, "not_due");
  assert.ok(result.remainingMs > 30 * 24 * 60 * 60 * 1000);
});

test("supervisor runOnce stays inert when the renewer is disabled", async () => {
  process.env.ACME_RENEWER_ENABLED = "false";
  const result = await runOnce();
  assert.equal(result.status, "skipped");
});

test("lineage continuity: bootstrapTls carries over a valid sealed capsule without any ACME order", async () => {
  enableRenewer();
  await seedCapsule({ keyPem: KEY_100Y, certPem: CERT_100Y, mintedAt: "2026-06-01T00:00:00.000Z", lineageId: "sha256:" + "a".repeat(64) });
  let mintCalls = 0;
  setRenewerDriversForTests({ runForcedRenewal: async () => { mintCalls += 1; throw new Error("must not mint"); } });

  const result = await bootstrapTls({ now: TODAY });
  assert.equal(result.status, "carried_over");
  assert.equal(mintCalls, 0);
  const material = getCurrentTlsMaterial();
  assert.equal(material.origin, "carried_over");
  assert.equal(material.keyPem, KEY_100Y);
  assert.equal(material.lineageId, "sha256:" + "a".repeat(64));
});

test("bootstrapTls mints in-enclave when no capsule exists (first genesis boot) and seals the result", async () => {
  enableRenewer();
  setRenewerDriversForTests({
    runForcedRenewal: async () => ({
      status: "renewed",
      material: { keyPem: KEY_200Y, certPem: CERT_200Y, mintedAt: TODAY.toISOString() },
      expiresAt: "2226-04-23T18:36:06.000Z",
    }),
  });

  const result = await bootstrapTls({ now: TODAY });
  assert.equal(result.status, "minted");
  const material = getCurrentTlsMaterial();
  assert.equal(material.origin, "minted_in_enclave");
  assert.equal(material.keyPem, KEY_200Y);
  assert.equal(material.lineageId, null);
  const capsule = storedCapsule();
  assert.ok(capsule, "fresh mint must be sealed for the next continuity boot");
  assert.ok(!JSON.stringify(capsule).includes(KEY_200Y));
});

test("crash-loop guard: a due capsule minted within the guard interval is carried over instead of re-minted", async () => {
  enableRenewer();
  const mintedAt = new Date(DUE_100Y.getTime() - 60 * 60 * 1000).toISOString();
  await seedCapsule({ keyPem: KEY_100Y, certPem: CERT_100Y, mintedAt, lineageId: null });
  let mintCalls = 0;
  setRenewerDriversForTests({ runForcedRenewal: async () => { mintCalls += 1; throw new Error("must not mint"); } });

  const result = await bootstrapTls({ now: DUE_100Y });
  assert.equal(result.status, "carried_over");
  assert.equal(mintCalls, 0);
});

test("bootstrapTls falls back to the still-valid (merely due) capsule cert when minting fails", async () => {
  enableRenewer();
  await seedCapsule({ keyPem: KEY_100Y, certPem: CERT_100Y, mintedAt: "2126-01-01T00:00:00.000Z", lineageId: null });
  setRenewerDriversForTests({ runForcedRenewal: async () => { throw new Error("LE rate limited"); } });

  const result = await bootstrapTls({ now: DUE_100Y });
  assert.equal(result.status, "fallback_carried_over");
  assert.equal(getCurrentTlsMaterial().origin, "carried_over");
});

test("bootstrapTls throws when minting fails and the capsule cert is expired", async () => {
  enableRenewer();
  await seedCapsule({ keyPem: KEY_100Y, certPem: CERT_100Y, mintedAt: "2126-01-01T00:00:00.000Z", lineageId: null });
  setRenewerDriversForTests({ runForcedRenewal: async () => { throw new Error("LE rate limited"); } });

  await assert.rejects(bootstrapTls({ now: EXPIRED_100Y }), /LE rate limited/);
  assert.equal(getCurrentTlsMaterial(), null);
});

test("bootstrapTls refuses to mint at boot in dry-run mode (LE rate-limit guard)", async () => {
  enableRenewer();
  process.env.ACME_RENEWER_DRY_RUN = "true";
  await assert.rejects(bootstrapTls({ now: TODAY }), /ACME_RENEWER_DRY_RUN/);
});

test("bootstrapTls in dry-run still carries over a valid capsule", async () => {
  enableRenewer();
  process.env.ACME_RENEWER_DRY_RUN = "true";
  await seedCapsule({ keyPem: KEY_100Y, certPem: CERT_100Y, mintedAt: "2026-06-01T00:00:00.000Z", lineageId: null });
  const result = await bootstrapTls({ now: TODAY });
  assert.equal(result.status, "carried_over");
});

test("bootstrapTls throws when minting is disabled and no capsule exists", async () => {
  process.env.ACME_RENEWER_ENABLED = "false";
  await assert.rejects(bootstrapTls({ now: TODAY }), /minting is unavailable/);
});

test("runOnce rotates the live secure context in place and re-seals the capsule (no VM reset)", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y, lineageId: "sha256:" + "a".repeat(64) }, { origin: "carried_over" });
  const rotations = [];
  setTlsServer({ setSecureContext: (context) => rotations.push(context) });
  setRenewerDriversForTests({
    renewIfDue: async () => ({
      status: "renewed",
      material: { keyPem: KEY_200Y, certPem: CERT_200Y, mintedAt: DUE_100Y.toISOString() },
      expiresAt: "2226-04-23T18:36:06.000Z",
    }),
  });

  const result = await runOnce({ now: DUE_100Y });
  assert.equal(result.status, "renewed");
  assert.equal(rotations.length, 1);
  assert.equal(rotations[0].key, KEY_200Y);
  assert.equal(rotations[0].cert, CERT_200Y);
  const material = getCurrentTlsMaterial();
  assert.equal(material.origin, "minted_in_enclave");
  assert.equal(material.lineageId, "sha256:" + "a".repeat(64), "renewal keeps the lineage anchor");
  assert.ok(storedCapsule(), "renewal must re-seal the capsule");
});

test("runOnce adopts a fresher cert from the shared capsule instead of double-minting (candidate convergence)", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y }, { origin: "minted_in_enclave" });
  await seedCapsule({ keyPem: KEY_200Y, certPem: CERT_200Y, mintedAt: DUE_100Y.toISOString(), lineageId: null });
  let mintCalls = 0;
  setRenewerDriversForTests({ renewIfDue: async () => { mintCalls += 1; throw new Error("must not mint"); } });

  const result = await runOnce({ now: DUE_100Y });
  assert.equal(result.status, "adopted_from_capsule");
  assert.equal(mintCalls, 0);
  assert.equal(getCurrentTlsMaterial().keyPem, KEY_200Y);
});

test("genesis with carried-over material schedules a forced re-mint bound to the new lineage anchor", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y, lineageId: "sha256:" + "0".repeat(64) }, { origin: "carried_over" });
  const newAnchor = "sha256:" + "1".repeat(64);
  let forcedCalls = 0;
  setRenewerDriversForTests({
    runForcedRenewal: async () => {
      forcedCalls += 1;
      return {
        status: "renewed",
        material: { keyPem: KEY_200Y, certPem: CERT_200Y, mintedAt: TODAY.toISOString() },
        expiresAt: "2226-04-23T18:36:06.000Z",
      };
    },
  });

  const result = await reconcileTlsWithLineage({ lineageId: newAnchor, event: "genesis" });
  assert.equal(result.status, "remint_scheduled");
  // The re-mint is kicked fire-and-forget; wait for it to land.
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(forcedCalls, 1);
  const material = getCurrentTlsMaterial();
  assert.equal(material.origin, "minted_in_enclave");
  assert.equal(material.keyPem, KEY_200Y, "genesis must never keep a carried-over cert");
  assert.equal(material.lineageId, newAnchor);
  assert.equal(storedCapsule().lineageId, newAnchor, "capsule must be re-sealed under the new anchor");
  assert.equal(getTlsRuntimeStatus().pendingRemint, null);
});

test("genesis with material minted by this enclave only re-binds and re-seals (already a fresh cert)", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_200Y, certPem: CERT_200Y, lineageId: null }, { origin: "minted_in_enclave" });
  const anchor = "sha256:" + "2".repeat(64);
  let forcedCalls = 0;
  setRenewerDriversForTests({ runForcedRenewal: async () => { forcedCalls += 1; throw new Error("must not mint"); } });

  const result = await reconcileTlsWithLineage({ lineageId: anchor, event: "genesis" });
  assert.equal(result.status, "rebound");
  assert.equal(forcedCalls, 0);
  assert.equal(getCurrentTlsMaterial().lineageId, anchor);
  assert.equal(storedCapsule().lineageId, anchor);
});

test("successor activation and capsule restore keep the carried-over cert when the anchors match", async () => {
  enableRenewer();
  const anchor = "sha256:" + "3".repeat(64);
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y, lineageId: anchor }, { origin: "carried_over" });
  let forcedCalls = 0;
  setRenewerDriversForTests({ runForcedRenewal: async () => { forcedCalls += 1; throw new Error("must not mint"); } });

  for (const event of ["successor_activation", "lineage_restore"]) {
    const result = await reconcileTlsWithLineage({ lineageId: anchor, event });
    assert.equal(result.status, "anchored");
  }
  assert.equal(forcedCalls, 0);
  assert.equal(getCurrentTlsMaterial().keyPem, KEY_100Y, "continuity must keep the carried-over in-enclave cert");
});

test("successor activation force-re-mints when the capsule anchor does not match the transferred lineage", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y, lineageId: "sha256:" + "4".repeat(64) }, { origin: "carried_over" });
  const transferredAnchor = "sha256:" + "5".repeat(64);
  setRenewerDriversForTests({
    runForcedRenewal: async () => ({
      status: "renewed",
      material: { keyPem: KEY_200Y, certPem: CERT_200Y, mintedAt: TODAY.toISOString() },
      expiresAt: "2226-04-23T18:36:06.000Z",
    }),
  });

  const result = await reconcileTlsWithLineage({ lineageId: transferredAnchor, event: "successor_activation" });
  assert.equal(result.status, "remint_scheduled");
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(getCurrentTlsMaterial().lineageId, transferredAnchor);
  assert.equal(getCurrentTlsMaterial().keyPem, KEY_200Y);
});

test("lineage restore binds an unanchored carried-over capsule to the restored lineage", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y, lineageId: null }, { origin: "carried_over" });
  const anchor = "sha256:" + "6".repeat(64);
  const result = await reconcileTlsWithLineage({ lineageId: anchor, event: "lineage_restore" });
  assert.equal(result.status, "rebound");
  assert.equal(getCurrentTlsMaterial().lineageId, anchor);
  assert.equal(getCurrentTlsMaterial().keyPem, KEY_100Y);
});

test("reconcileTlsWithLineage is a safe no-op when the renewer is disabled (test/gov-route environments)", async () => {
  process.env.ACME_RENEWER_ENABLED = "false";
  const result = await reconcileTlsWithLineage({ lineageId: "sha256:" + "7".repeat(64), event: "genesis" });
  assert.equal(result.status, "skipped");
});

test("renewer envelope canonical form is stable", async () => {
  const { canonicalStringify } = await import("../src/canonical-json.js");
  const payload = {
    schema: "femled.authoritative_dns_tee.external_tee_renewer.payload.v1",
    callerName: "auth-broker-tee",
    callerImageDigest: "sha256:" + "a".repeat(64),
    attestationToken: "test-token",
    attestationDigest: "sha256:" + "b".repeat(64),
    route: "/governance/routine-zone-change-renewer",
    change: {
      class: "IN",
      name: "_acme-challenge.oauth-tee.femled.ai.",
      op: "add",
      ttl: 60,
      type: "TXT",
      values: ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNopq"],
    },
    changeDigest: "sha256:" + "c".repeat(64),
    requestNonce: "test-nonce-" + crypto.randomBytes(8).toString("base64url"),
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  };
  const canonical = canonicalStringify(payload);
  assert.match(canonical, /auth-broker-tee/);
  assert.match(canonical, /_acme-challenge\.oauth-tee\.femled\.ai/);
});

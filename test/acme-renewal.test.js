import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test, beforeEach, afterEach } from "node:test";
import { adoptTlsMaterial, getCurrentTlsMaterial, resetTlsMaterialForTests, setTlsServer } from "../src/tls-material.js";
import { setMintLogTransportForTests, resetMintLogForTests, MINT_LOG_OBJECT, MINT_LOG_SCHEMA } from "../src/tls-mint-log.js";

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

const TEST_BUCKET = "test-capsule-bucket";

const ORIGINAL_ENV = {
  ACME_RENEWER_ENABLED: process.env.ACME_RENEWER_ENABLED,
  ACME_RENEWER_DRY_RUN: process.env.ACME_RENEWER_DRY_RUN,
  RENEWER_KMS_SIGNER_KEY_VERSION: process.env.RENEWER_KMS_SIGNER_KEY_VERSION,
  DNS_TEE_RENEWER_URLS: process.env.DNS_TEE_RENEWER_URLS,
  CAPSULE_BUCKET: process.env.CAPSULE_BUCKET,
  TLS_MAX_MINTS_PER_WEEK: process.env.TLS_MAX_MINTS_PER_WEEK,
};

// In-memory fake for the non-secret TLS mint ledger (timestamps only).
let mintLogStore;
function installFakeMintLog() {
  mintLogStore = new Map();
  setMintLogTransportForTests({
    readObject: async (bucket, objectName) => mintLogStore.get(`${bucket}/${objectName}`) ?? null,
    writeObject: async (bucket, objectName, value) => {
      mintLogStore.set(`${bucket}/${objectName}`, JSON.parse(JSON.stringify(value)));
    },
  });
}
function seedMintLog(timestamps) {
  mintLogStore.set(`${TEST_BUCKET}/${MINT_LOG_OBJECT}`, { schema: MINT_LOG_SCHEMA, mints: timestamps });
}
function mintLogEntries() {
  return mintLogStore.get(`${TEST_BUCKET}/${MINT_LOG_OBJECT}`)?.mints ?? [];
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
  process.env.CAPSULE_BUCKET = TEST_BUCKET;
  delete process.env.TLS_MAX_MINTS_PER_WEEK;
  setDnsTeeFetcherForTests(null);
  setRenewerEnvelopeBuilderForTests(null);
  setRenewerDriversForTests(null);
  resetTlsMaterialForTests();
  resetTlsSupervisorForTests();
  resetMintLogForTests();
  installFakeMintLog();
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
  resetMintLogForTests();
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

test("renewIfDue reads the renewal window from the IN-MEMORY cert (no persistence)", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y });
  const result = await renewIfDue({ now: TODAY });
  assert.equal(result.status, "not_due");
  assert.ok(result.remainingMs > 30 * 24 * 60 * 60 * 1000);
});

test("supervisor runOnce stays inert when the renewer is disabled", async () => {
  process.env.ACME_RENEWER_ENABLED = "false";
  const result = await runOnce();
  assert.equal(result.status, "skipped");
});

test("bootstrapTls always mints a fresh in-enclave cert and records the mint (no capsule, nothing persisted)", async () => {
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
  assert.equal(material.keyPem, KEY_200Y);
  // The mint is recorded in the non-secret ledger (timestamp only, no key).
  const entries = mintLogEntries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0], TODAY.toISOString());
  assert.ok(!JSON.stringify(mintLogStore.get(`${TEST_BUCKET}/${MINT_LOG_OBJECT}`)).includes(KEY_200Y));
});

test("bootstrapTls refuses to attempt an order once the issuance token bucket is empty", async () => {
  enableRenewer();
  // Five successful mints within a few hours empty LE's token bucket.
  const base = TODAY.getTime();
  seedMintLog([1, 2, 3, 4, 5].map((h) => new Date(base - h * 60 * 60 * 1000).toISOString()));
  let mintCalls = 0;
  setRenewerDriversForTests({ runForcedRenewal: async () => { mintCalls += 1; throw new Error("must not mint"); } });

  await assert.rejects(bootstrapTls({ now: TODAY }), /issuance budget exhausted/);
  assert.equal(mintCalls, 0, "must not send an order LE would reject");
});

test("bootstrapTls mints when older mints have aged out of the 7-day window", async () => {
  enableRenewer();
  const base = TODAY.getTime();
  // Five mints, but all older than 7 days -> pruned, budget available again.
  seedMintLog([8, 9, 10, 11, 12].map((d) => new Date(base - d * 24 * 60 * 60 * 1000).toISOString()));
  setRenewerDriversForTests({
    runForcedRenewal: async () => ({
      status: "renewed",
      material: { keyPem: KEY_200Y, certPem: CERT_200Y, mintedAt: TODAY.toISOString() },
      expiresAt: "2226-04-23T18:36:06.000Z",
    }),
  });

  const result = await bootstrapTls({ now: TODAY });
  assert.equal(result.status, "minted");
  assert.equal(mintLogEntries().length, 1, "aged-out entries are pruned before appending the fresh mint");
});

test("bootstrapTls throws when minting is disabled (no capsule fallback exists)", async () => {
  process.env.ACME_RENEWER_ENABLED = "false";
  await assert.rejects(bootstrapTls({ now: TODAY }), /minting is unavailable/);
  assert.equal(getCurrentTlsMaterial(), null);
});

test("bootstrapTls refuses to mint at boot in dry-run mode (LE rate-limit guard)", async () => {
  enableRenewer();
  process.env.ACME_RENEWER_DRY_RUN = "true";
  await assert.rejects(bootstrapTls({ now: TODAY }), /ACME_RENEWER_DRY_RUN/);
});

test("bootstrapTls rethrows the mint error when all attempts fail (no persisted fallback)", async () => {
  enableRenewer();
  setRenewerDriversForTests({ runForcedRenewal: async () => { throw new Error("LE rate limited"); } });
  await assert.rejects(bootstrapTls({ now: TODAY }), /LE rate limited/);
  assert.equal(getCurrentTlsMaterial(), null);
});

test("runOnce rotates the live secure context in place on renewal (no VM reset, nothing sealed)", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y });
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
  assert.equal(getCurrentTlsMaterial().keyPem, KEY_200Y);
  // A steady-state renewal is also a real LE issuance -> recorded in the ledger.
  assert.equal(mintLogEntries().length, 1);
});

test("getTlsRuntimeStatus exposes in-memory material and the mint ledger, never a capsule", async () => {
  enableRenewer();
  adoptTlsMaterial({ keyPem: KEY_100Y, certPem: CERT_100Y, mintedAt: TODAY.toISOString() });
  const status = getTlsRuntimeStatus();
  assert.equal(status.material.adopted, true);
  assert.ok(status.mintLog, "runtime status surfaces the mint ledger");
  assert.equal(status.capsule, undefined, "there is no TLS capsule in the ephemeral model");
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

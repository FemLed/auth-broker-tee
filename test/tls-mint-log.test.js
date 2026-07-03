import assert from "node:assert/strict";
import { test, beforeEach, afterEach } from "node:test";
import {
  assertMintWithinWeeklyBudget,
  recordSuccessfulMint,
  getMintLogStatus,
  setMintLogTransportForTests,
  resetMintLogForTests,
  MINT_LOG_OBJECT,
  MINT_LOG_SCHEMA,
} from "../src/tls-mint-log.js";

const TEST_BUCKET = "test-capsule-bucket";
const NOW = new Date("2026-06-11T00:00:00Z");

const ORIGINAL_ENV = {
  CAPSULE_BUCKET: process.env.CAPSULE_BUCKET,
  TLS_MAX_MINTS_PER_WEEK: process.env.TLS_MAX_MINTS_PER_WEEK,
};

let store;
function key() {
  return `${TEST_BUCKET}/${MINT_LOG_OBJECT}`;
}
function seed(timestamps) {
  store.set(key(), { schema: MINT_LOG_SCHEMA, mints: timestamps });
}
function installFake({ failRead = false, failWrite = false } = {}) {
  store = new Map();
  setMintLogTransportForTests({
    readObject: async (bucket, objectName) => {
      if (failRead) throw new Error("gcs read down");
      return store.get(`${bucket}/${objectName}`) ?? null;
    },
    writeObject: async (bucket, objectName, value) => {
      if (failWrite) throw new Error("gcs write down");
      store.set(`${bucket}/${objectName}`, JSON.parse(JSON.stringify(value)));
    },
  });
}

beforeEach(() => {
  process.env.CAPSULE_BUCKET = TEST_BUCKET;
  delete process.env.TLS_MAX_MINTS_PER_WEEK;
  resetMintLogForTests();
  installFake();
});

afterEach(() => {
  for (const [k, v] of Object.entries(ORIGINAL_ENV)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  resetMintLogForTests();
});

test("assertMintWithinWeeklyBudget allows a mint when under the weekly ceiling", async () => {
  seed([new Date(NOW.getTime() - 60 * 60 * 1000).toISOString()]);
  await assert.doesNotReject(assertMintWithinWeeklyBudget({ now: NOW }));
});

test("assertMintWithinWeeklyBudget throws once the weekly ceiling is reached", async () => {
  const base = NOW.getTime();
  seed([1, 2, 3, 4, 5].map((h) => new Date(base - h * 60 * 60 * 1000).toISOString()));
  await assert.rejects(assertMintWithinWeeklyBudget({ now: NOW }), /weekly mint budget reached/);
});

test("entries older than 7 days are pruned and do not count toward the budget", async () => {
  const base = NOW.getTime();
  seed([8, 9, 10, 11, 12].map((d) => new Date(base - d * 24 * 60 * 60 * 1000).toISOString()));
  await assert.doesNotReject(assertMintWithinWeeklyBudget({ now: NOW }));
});

test("a lower TLS_MAX_MINTS_PER_WEEK reserves headroom", async () => {
  process.env.TLS_MAX_MINTS_PER_WEEK = "2";
  const base = NOW.getTime();
  seed([1, 2].map((h) => new Date(base - h * 60 * 60 * 1000).toISOString()));
  await assert.rejects(assertMintWithinWeeklyBudget({ now: NOW }), /2\/2/);
});

test("assertMintWithinWeeklyBudget fails OPEN when the ledger cannot be read", async () => {
  installFake({ failRead: true });
  await assert.doesNotReject(assertMintWithinWeeklyBudget({ now: NOW }));
  assert.match(getMintLogStatus().readError, /gcs read down/);
});

test("recordSuccessfulMint appends a timestamp (and only a timestamp)", async () => {
  await recordSuccessfulMint({ now: NOW });
  const doc = store.get(key());
  assert.equal(doc.schema, MINT_LOG_SCHEMA);
  assert.deepEqual(doc.mints, [NOW.toISOString()]);
  // The ledger must never contain anything but timestamps.
  assert.equal(Object.keys(doc).sort().join(","), "mints,schema");
});

test("recordSuccessfulMint is best-effort and never throws on a write failure", async () => {
  installFake({ failWrite: true });
  await assert.doesNotReject(recordSuccessfulMint({ now: NOW }));
});

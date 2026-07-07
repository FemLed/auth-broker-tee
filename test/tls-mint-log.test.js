import assert from "node:assert/strict";
import { test, beforeEach, afterEach } from "node:test";
import {
  assertMintWithinWeeklyBudget,
  recordSuccessfulMint,
  getMintLogStatus,
  setMintLogTransportForTests,
  resetMintLogForTests,
  tokensAvailable,
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

test("assertMintWithinWeeklyBudget allows a mint when tokens remain", async () => {
  seed([new Date(NOW.getTime() - 60 * 60 * 1000).toISOString()]);
  await assert.doesNotReject(assertMintWithinWeeklyBudget({ now: NOW }));
});

test("assertMintWithinWeeklyBudget throws when a tight reboot loop empties the bucket", async () => {
  const base = NOW.getTime();
  seed([1, 2, 3, 4, 5].map((h) => new Date(base - h * 60 * 60 * 1000).toISOString()));
  await assert.rejects(assertMintWithinWeeklyBudget({ now: NOW }), /issuance budget exhausted/);
});

test("the blocked-boot error names the next-token time so operators can see when it self-heals", async () => {
  const base = NOW.getTime();
  seed([1, 2, 3, 4, 5].map((h) => new Date(base - h * 60 * 60 * 1000).toISOString()));
  await assert.rejects(assertMintWithinWeeklyBudget({ now: NOW }), /Next token at ~2026-06-1\dT/);
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
  await assert.rejects(assertMintWithinWeeklyBudget({ now: NOW }), /\/2 tokens/);
});

// Regression: the 2026-07-07 outage. Five real mints spread over four days
// (2 on 7/3 from ephemeral-TLS rollout reboots, then one per crash-reboot on
// 7/4, 7/6, 7/7). The old strict trailing-7d count saw 5/5 and fail-closed
// the boot until 7/10, but LE's token bucket had ~2.8 tokens available; the
// GCRA simulation must allow this boot.
const OUTAGE_MINTS = [
  "2026-07-03T12:51:41.834Z",
  "2026-07-03T15:09:55.774Z",
  "2026-07-04T13:01:56.105Z",
  "2026-07-06T15:48:36.128Z",
  "2026-07-07T08:17:44.978Z",
];
const OUTAGE_BOOT = new Date("2026-07-07T10:56:00Z");

test("regression: mints spread out per LE's refill rate do not block the boot (2026-07-07 outage)", async () => {
  seed(OUTAGE_MINTS);
  await assert.doesNotReject(assertMintWithinWeeklyBudget({ now: OUTAGE_BOOT }));
  const status = getMintLogStatus();
  assert.equal(status.windowCount, 5);
  assert.ok(status.tokensAvailable > 2.5 && status.tokensAvailable < 3.1,
    `expected ~2.8 tokens, got ${status.tokensAvailable}`);
});

test("tokensAvailable models the GCRA bucket: full on no history, capped at max, empty on a burst", () => {
  assert.equal(tokensAvailable([], { now: NOW }), 5);
  // A single ancient mint has fully refilled (and never exceeds capacity).
  assert.equal(tokensAvailable([new Date(NOW.getTime() - 6.9 * 24 * 60 * 60 * 1000).toISOString()], { now: NOW }), 5);
  // Five mints in the same minute drain the bucket to ~0.
  const burst = [0, 1, 2, 3, 4].map((m) => new Date(NOW.getTime() - (5 - m) * 60 * 1000).toISOString());
  assert.ok(tokensAvailable(burst, { now: NOW }) < 0.01);
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

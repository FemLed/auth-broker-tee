// Non-secret, cold-boot-durable Let's Encrypt mint ledger.
//
// Ephemeral TLS (no sealed capsule) means every cold boot mints a fresh cert,
// so a reboot loop could exhaust Let's Encrypt's "new certificates per exact
// set of identifiers" limit and lock the service out of getting a cert at
// all. This ledger records ONLY mint TIMESTAMPS -- never key material, never
// the certificate -- in the capsule bucket, so a fresh boot can see recent
// mint history and refuse to attempt an order Let's Encrypt would reject
// anyway.
//
// The boot guard models LE's ACTUAL enforcement, which is a GCRA token
// bucket: capacity `TLS_MAX_MINTS_PER_WEEK` (default 5, matching LE's
// published limit) refilling continuously at capacity/7d (1 token per 33.6h
// at the default). A strict "5 in the trailing 7 days" count is up to ~3
// days more conservative than LE itself; on 2026-07-07 that gap kept the
// broker fail-closed in a reboot loop while LE already had ~2.8 tokens
// available for oauth-tee.femled.ai. The 7-day retention window is
// sufficient history for the simulation: any deficit fully refills within
// capacity * refill-interval = 7 days, so a bucket that starts full at the
// window edge cannot owe anything to older mints.
//
// It is a non-secret availability aid, not a security boundary: a hostile
// bucket owner tampering with it can only affect availability (already a
// declared non-goal), never confidentiality. Nothing here is sealed, and there
// is no key to recover.

import { readGcsObjectJson, writeGcsObjectJson } from "./gcp-auth.js";

export const MINT_LOG_OBJECT = "tls/mint-log.v1.json";
export const MINT_LOG_SCHEMA = "femled.tee.tls_mint_log.v1";
const WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// Bucket capacity. The default mirrors LE's ceiling; lowering it (env)
// reserves headroom for recovery at the cost of blocking otherwise-legal
// reboots.
function maxMintsPerWindow() {
  return Number(process.env.TLS_MAX_MINTS_PER_WEEK || 5);
}

function refillIntervalMs(max) {
  return WINDOW_MS / max;
}

function capsuleBucket() {
  return process.env.CAPSULE_BUCKET || "prod-femled-couple-router-auth-broker-tee-governance-capsules";
}

const defaultTransport = {
  readObject: (bucket, objectName) => readGcsObjectJson(bucket, objectName),
  writeObject: (bucket, objectName, value) => writeGcsObjectJson(bucket, objectName, value),
};
let transport = defaultTransport;

export function setMintLogTransportForTests(overrides) {
  transport = overrides ? { ...defaultTransport, ...overrides } : defaultTransport;
}

let lastStatus = { lastMintAt: null, windowCount: 0, tokensAvailable: null, readError: null };

export function resetMintLogForTests() {
  transport = defaultTransport;
  lastStatus = { lastMintAt: null, windowCount: 0, tokensAvailable: null, readError: null };
}

async function readMintTimestamps() {
  const doc = await transport.readObject(capsuleBucket(), MINT_LOG_OBJECT);
  if (!doc || doc.schema !== MINT_LOG_SCHEMA || !Array.isArray(doc.mints)) return [];
  return doc.mints.filter((entry) => typeof entry === "string" && Number.isFinite(Date.parse(entry)));
}

function pruneToWindow(mints, now) {
  const cutoff = now.getTime() - WINDOW_MS;
  return mints
    .filter((entry) => Date.parse(entry) >= cutoff)
    .sort();
}

// Simulates LE's token bucket over the (ascending) mint history: start full,
// subtract one token per recorded mint, refill continuously between events,
// cap at capacity. Recorded mints were all LE-accepted, so clamping at zero
// only absorbs clock skew between our records and LE's accounting.
export function tokensAvailable(mints, { now = new Date(), max = maxMintsPerWindow() } = {}) {
  const refillMs = refillIntervalMs(max);
  let tokens = max;
  let cursor = null;
  for (const entry of mints) {
    const at = Date.parse(entry);
    if (!Number.isFinite(at)) continue;
    if (cursor !== null && at > cursor) {
      tokens = Math.min(max, tokens + (at - cursor) / refillMs);
    }
    cursor = cursor === null ? at : Math.max(cursor, at);
    tokens = Math.max(0, tokens - 1);
  }
  if (cursor !== null && now.getTime() > cursor) {
    tokens = Math.min(max, tokens + (now.getTime() - cursor) / refillMs);
  }
  return tokens;
}

function roundTokens(tokens) {
  return Math.round(tokens * 100) / 100;
}

// Boot guard: throws when the simulated bucket holds less than one whole
// token, so we fail fast instead of sending a doomed order (which would only
// add to LE's failed-order accounting). Unlike the previous strict trailing-7d
// count, a blocked boot self-heals as soon as LE itself would issue again
// (next token at most 33.6h out at default capacity, never 3 days). Fails
// OPEN on a read error -- a transient GCS blip must not block getting a cert.
export async function assertMintWithinWeeklyBudget({ now = new Date() } = {}) {
  let mints;
  try {
    mints = pruneToWindow(await readMintTimestamps(), now);
  } catch (error) {
    lastStatus = { ...lastStatus, readError: String(error.message || error).slice(0, 256) };
    console.error("[TLS mint-log] read failed; proceeding to mint (fail-open):", error.message);
    return;
  }
  const max = maxMintsPerWindow();
  const tokens = tokensAvailable(mints, { now, max });
  lastStatus = {
    lastMintAt: mints[mints.length - 1] || null,
    windowCount: mints.length,
    tokensAvailable: roundTokens(tokens),
    readError: null,
  };
  if (tokens < 1) {
    const nextTokenAt = new Date(now.getTime() + (1 - tokens) * refillIntervalMs(max));
    throw new Error(
      `Let's Encrypt issuance budget exhausted (${roundTokens(tokens)}/${max} tokens; ` +
      `${mints.length} mints in the trailing 7 days, refill 1 per ${(refillIntervalMs(max) / 3_600_000).toFixed(1)}h); ` +
      `refusing to attempt an order Let's Encrypt would reject. Next token at ~${nextTokenAt.toISOString()}. ` +
      "Investigate the reboot loop if these mints are unexpected.",
    );
  }
}

// Records a SUCCESSFUL mint. Best-effort: a write failure must never fail a boot
// that already holds good in-memory material (the ledger may then undercount,
// which only weakens the guard, never confidentiality).
export async function recordSuccessfulMint({ now = new Date() } = {}) {
  try {
    const mints = pruneToWindow(await readMintTimestamps(), now);
    mints.push(now.toISOString());
    await transport.writeObject(capsuleBucket(), MINT_LOG_OBJECT, { schema: MINT_LOG_SCHEMA, mints });
    lastStatus = {
      lastMintAt: now.toISOString(),
      windowCount: mints.length,
      tokensAvailable: roundTokens(tokensAvailable(mints, { now })),
      readError: null,
    };
  } catch (error) {
    console.error("[TLS mint-log] record failed (best-effort; ledger may undercount):", error.message);
  }
}

export function getMintLogStatus() {
  return {
    schema: "femled.tee.tls_mint_log_status.v1",
    ...lastStatus,
    maxPerWeek: maxMintsPerWindow(),
  };
}

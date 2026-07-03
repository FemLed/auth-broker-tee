// Non-secret, cold-boot-durable Let's Encrypt mint ledger.
//
// Ephemeral TLS (no sealed capsule) means every cold boot mints a fresh cert,
// so a reboot loop could burn Let's Encrypt's "certificates per exact set of
// identifiers" weekly limit (5 per 7 days, refilling ~1 per 34h) and lock the
// service out of getting a cert at all. This ledger records ONLY mint
// TIMESTAMPS -- never key material, never the certificate -- in the capsule
// bucket, so a fresh boot can see recent mint history and refuse to attempt an
// order Let's Encrypt would reject anyway.
//
// It is a non-secret availability aid, not a security boundary: a hostile
// bucket owner tampering with it can only affect availability (already a
// declared non-goal), never confidentiality. Nothing here is sealed, and there
// is no key to recover.

import { readGcsObjectJson, writeGcsObjectJson } from "./gcp-auth.js";

export const MINT_LOG_OBJECT = "tls/mint-log.v1.json";
export const MINT_LOG_SCHEMA = "femled.tee.tls_mint_log.v1";
const WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// Let's Encrypt allows 5 certs per exact set of identifiers per 7 days. The
// default mirrors that ceiling so we never send an order LE would reject;
// lowering it (env) reserves headroom for recovery at the cost of blocking
// otherwise-legal reboots.
function maxMintsPerWindow() {
  return Number(process.env.TLS_MAX_MINTS_PER_WEEK || 5);
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

let lastStatus = { lastMintAt: null, windowCount: 0, readError: null };

export function resetMintLogForTests() {
  transport = defaultTransport;
  lastStatus = { lastMintAt: null, windowCount: 0, readError: null };
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

// Boot guard: throws when the trailing-7d successful-mint count is at/over the
// Let's Encrypt weekly ceiling, so we fail fast instead of sending a doomed
// order (which would only add to LE's failed-order accounting). Fails OPEN on a
// read error -- a transient GCS blip must not block getting a cert.
export async function assertMintWithinWeeklyBudget({ now = new Date() } = {}) {
  let mints;
  try {
    mints = pruneToWindow(await readMintTimestamps(), now);
  } catch (error) {
    lastStatus = { ...lastStatus, readError: String(error.message || error).slice(0, 256) };
    console.error("[TLS mint-log] read failed; proceeding to mint (fail-open):", error.message);
    return;
  }
  lastStatus = { lastMintAt: mints[mints.length - 1] || null, windowCount: mints.length, readError: null };
  const max = maxMintsPerWindow();
  if (mints.length >= max) {
    throw new Error(
      `Let's Encrypt weekly mint budget reached (${mints.length}/${max} in the trailing 7 days); ` +
      "refusing to attempt an order Let's Encrypt would reject. Wait for the ~34h refill or investigate the reboot loop.",
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
    lastStatus = { lastMintAt: now.toISOString(), windowCount: mints.length, readError: null };
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

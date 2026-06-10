// Sealed in-enclave TLS: in-TEE ACME DNS-01 renewer + supervisor
// (auth-broker-tee port).
//
// Owns the lifecycle of this TEE's TLS material for `oauth-tee.femled.ai`:
//
//   boot        bootstrapTls(): lineage-continuity boots (successor
//               activations, roll candidates, same-image restarts) unseal the
//               attestation-gated capsule (tls-capsule.js) and carry the
//               existing in-enclave cert forward WITHOUT a Let's Encrypt
//               order; an ACME mint runs only when no usable capsule exists
//               (first genesis boot) or the carried cert is expired/inside
//               the renewal window.
//   renewal     runOnce() on a 24h cadence: when due, re-reads the shared
//               capsule first (a roll candidate may already have renewed --
//               adopt instead of double-minting against the LE duplicate-cert
//               quota), otherwise orders a fresh cert, rotates the live
//               listener in place via server.setSecureContext() (the hot
//               reload is BACK; the interim compute.instances.reset reload
//               contract is gone along with its IAM grant), and re-seals the
//               capsule.
//   lineage     reconcileTlsWithLineage(): invoked (fire-and-forget) by
//               governance-state.js after a genesis bootstrap, a successor
//               activation-apply, or a cold-start capsule restore. Genesis
//               events ALWAYS get a fresh ACME cert: carried-over material is
//               force-re-minted and the capsule re-sealed under the new
//               lineage anchor; material minted by this very enclave is
//               already fresh and is only re-bound. Continuity events keep
//               the carried-over cert after verifying the capsule's lineage
//               anchor matches the governance lineage.
//
// The leaf private key is generated inside the TEE and NEVER persisted in
// plaintext; there is no Secret Manager read or write for TLS material
// anywhere in this path. DNS-01 rides authoritative-dns-tee's
// external-TEE-renewer trust path for the `_acme-challenge.oauth-tee.femled.ai`
// TXT writes.

import acme from "acme-client";
import { loadOrCreateAcmeAccountKey } from "./acme-account.js";
import { buildRenewerEnvelope, RENEWER_HOST } from "./renewer-governance-signer.js";
import {
  adoptTlsMaterial,
  getCurrentTlsMaterial,
  getCurrentCertExpiry,
  certExpiryFromPem,
  setTlsLineageId,
  getTlsMaterialStatus,
} from "./tls-material.js";
import { sealTlsMaterial, unsealTlsMaterial, getTlsCapsuleStatus } from "./tls-capsule.js";

const RENEWER_ROUTE = "/governance/routine-zone-change-renewer";
const RENEWER_TXT_TTL = 60;
const RENEWAL_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const RENEWAL_THRESHOLD_DAYS = 30;
const ACME_DIRECTORY_URL = process.env.ACME_DIRECTORY_URL || acme.directory.letsencrypt.production;
const ACME_CONTACT_EMAIL = process.env.ACME_CONTACT_EMAIL || "engineering@femled.ai";
// The DNS-TEE governance/renewer API is served on HTTP port 8080 (its firewall
// only exposes 8080 for the governance route; there is no 443 listener), so the
// fan-out targets must be the :8080 governance endpoints.
const DNS_TEE_RENEWER_URLS = (process.env.DNS_TEE_RENEWER_URLS || "http://ns1.femled.ai:8080,http://ns2.femled.ai:8080,http://ns3.femled.ai:8080,http://ns4.femled.ai:8080").split(",").map((url) => url.trim()).filter(Boolean);

// submitRenewerChange only resolves once ALL four DNS-TEE slots return APPROVE,
// and each slot signs + writes + reloads NSD with the change BEFORE returning
// APPROVE, so all-four-APPROVE already means every authoritative slot is serving
// the challenge TXT. We cannot verify via direct DNS from this enclave
// (node:dns is a forbidden import here), so after the all-APPROVE fan-out we
// wait a short settle window to cover NSD reload-to-serving + the validator's
// query timing, then let Boulder validate authoritatively.
const RENEWER_POST_APPROVE_SETTLE_MS = Number(process.env.ACME_POST_APPROVE_SETTLE_MS || 15_000);
const RENEWER_HOST_LABEL = RENEWER_HOST.replace(/\.$/, "");

// Boot crash-loop guard: a capsule cert minted within this interval is always
// carried over (even if already inside the renewal window) instead of spending
// another order against LE's 5/week duplicate-certificate quota.
const TLS_BOOT_REMINT_MIN_INTERVAL_MS = Number(process.env.TLS_BOOT_REMINT_MIN_INTERVAL_MS || 24 * 60 * 60 * 1000);

// Boot-time bootstrap retries: several ACME order attempts per boot before
// giving up (and letting the VM crashloop into a fresh boot).
const BOOTSTRAP_MAX_ATTEMPTS = Number(process.env.ACME_BOOTSTRAP_MAX_ATTEMPTS || 6);
const BOOTSTRAP_RETRY_DELAY_MS = Number(process.env.ACME_BOOTSTRAP_RETRY_DELAY_MS || 20_000);

let inFlight = false;
let timer = null;

// A lineage-driven re-mint request (genesis must never inherit a carried-over
// cert; anchor mismatch on activation/restore is treated the same way).
// Survives failed attempts so every supervisor cycle retries until it lands.
let pendingRemint = null;

let dnsTeeFetcher = (url, init) => fetch(url, init);
export function setDnsTeeFetcherForTests(fetcher) {
  dnsTeeFetcher = fetcher || ((url, init) => fetch(url, init));
}

let envelopeBuilderOverride = null;
export function setRenewerEnvelopeBuilderForTests(builder) {
  envelopeBuilderOverride = builder || null;
}
function activeEnvelopeBuilder() {
  return envelopeBuilderOverride || buildRenewerEnvelope;
}

let renewerDrivers = { renewIfDue, runForcedRenewal };
export function setRenewerDriversForTests(drivers) {
  renewerDrivers = drivers
    ? { renewIfDue, runForcedRenewal, ...drivers }
    : { renewIfDue, runForcedRenewal };
}

export function resetTlsSupervisorForTests() {
  pendingRemint = null;
  inFlight = false;
}

export function getTlsRuntimeStatus() {
  return {
    schema: "femled.auth_broker_tee.tls_runtime.v1",
    material: getTlsMaterialStatus(),
    capsule: getTlsCapsuleStatus(),
    pendingRemint,
  };
}

// Renewer gates are read lazily (not at module load) so tests and staged
// enablement see current process.env values.
function renewerSkipReason() {
  if (process.env.ACME_RENEWER_ENABLED !== "true") {
    return "ACME_RENEWER_ENABLED is false";
  }
  if (!process.env.RENEWER_KMS_SIGNER_KEY_VERSION) {
    return "RENEWER_KMS_SIGNER_KEY_VERSION is not configured";
  }
  return null;
}

function isDryRun() {
  return process.env.ACME_RENEWER_DRY_RUN === "true";
}

export function startRenewalLoop() {
  if (timer) return;
  if (renewerSkipReason()) {
    console.log(`[ACME] renewer supervisor not started: ${renewerSkipReason()}`);
    return;
  }
  runOnce().catch((error) => {
    console.error("[ACME] startup cycle failed:", error.message);
  });
  timer = setInterval(() => {
    runOnce().catch((error) => {
      console.error("[ACME] periodic cycle failed:", error.message);
    });
  }, RENEWAL_CHECK_INTERVAL_MS);
}

export function stopRenewalLoop() {
  if (timer) clearInterval(timer);
  timer = null;
}

// Boot-time, one-shot in-enclave TLS bootstrap. Runs BEFORE the HTTPS listener
// binds; the adopted material lives only in process memory.
//
// Order of preference:
//   1. Carry over the sealed capsule when its cert is valid and not yet inside
//      the renewal window (or was minted within the boot crash-loop guard
//      interval). This is the lineage-continuity path: successor activations
//      and candidate VMs never spend a Let's Encrypt order at boot.
//   2. Mint in-enclave via ACME DNS-01 (first genesis boot, or carried cert
//      expired/due), then seal the capsule (best-effort) so the next boot is a
//      continuity boot.
//   3. If minting fails but the capsule cert is still VALID (merely due),
//      serve it and let the supervisor loop retry the renewal.
//
// Dry-run must NOT issue at boot: runRenewal() performs a full real ACME order
// against the LE production directory and only checks the dry-run flag
// afterward, returning without material. Issuing in dry-run at boot would
// leave TLS unadopted, crashloop the VM, and re-issue a real prod cert every
// loop -> LE Duplicate Certificate rate limit.
export async function bootstrapTls({ now = new Date() } = {}) {
  let capsule = null;
  try {
    capsule = await unsealTlsMaterial();
  } catch (error) {
    // Unreadable/undecryptable capsule (e.g. first boot of an image outside
    // the sealing key's digest window, or a torn write). Treat as absent and
    // mint; the fresh seal below replaces it.
    console.error("[TLS bootstrap] sealed capsule unseal failed (treating as absent):", error.message);
  }

  const nowMs = now.getTime();
  const renewalWindowMs = RENEWAL_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
  const capsuleExpiry = capsule ? certExpiryFromPem(capsule.certPem) : null;
  const capsuleValidMs = capsuleExpiry ? capsuleExpiry.getTime() - nowMs : -Infinity;
  const capsuleValid = capsuleValidMs > 0;
  const capsuleDue = capsuleValidMs <= renewalWindowMs;
  const capsuleMintedAgoMs = capsule?.mintedAt ? nowMs - Date.parse(capsule.mintedAt) : Infinity;
  const withinCrashLoopGuard = Number.isFinite(capsuleMintedAgoMs)
    && capsuleMintedAgoMs >= 0
    && capsuleMintedAgoMs < TLS_BOOT_REMINT_MIN_INTERVAL_MS;

  if (capsule && capsuleValid && (!capsuleDue || withinCrashLoopGuard)) {
    adoptTlsMaterial(capsule, { origin: "carried_over" });
    const days = Math.round(capsuleValidMs / (24 * 60 * 60 * 1000));
    console.log(`[TLS bootstrap] lineage continuity: carried over sealed in-enclave cert (~${days}d remaining, lineage ${capsule.lineageId || "unanchored"}); no ACME order`);
    return { status: "carried_over", expiresAt: capsuleExpiry.toISOString(), lineageId: capsule.lineageId ?? null };
  }

  const canMint = !renewerSkipReason() && !isDryRun();
  if (!canMint) {
    if (capsule && capsuleValid) {
      adoptTlsMaterial(capsule, { origin: "carried_over" });
      console.error("[TLS bootstrap] carried over a cert that is already inside the renewal window, but minting is unavailable (renewer disabled or dry-run); renewal will strand without operator action");
      return { status: "carried_over_due", expiresAt: capsuleExpiry.toISOString(), lineageId: capsule.lineageId ?? null };
    }
    const reason = isDryRun()
      ? "ACME_RENEWER_DRY_RUN is set (boot path issues only adoptable certs)"
      : renewerSkipReason();
    throw new Error(`no usable sealed TLS capsule and in-enclave minting is unavailable: ${reason}`);
  }

  let lastError = null;
  for (let attempt = 1; attempt <= BOOTSTRAP_MAX_ATTEMPTS; attempt += 1) {
    try {
      const result = await renewerDrivers.runForcedRenewal();
      if (result.status === "renewed") {
        // Carry the previous capsule's lineage anchor forward: a boot-time
        // re-mint does not change which governance lineage this service is.
        // (A genesis event re-binds via reconcileTlsWithLineage.)
        const lineageId = capsule?.lineageId ?? null;
        adoptTlsMaterial({ ...result.material, lineageId }, { origin: "minted_in_enclave" });
        await sealCurrentTlsMaterial("boot mint");
        console.log("[TLS bootstrap] in-enclave ACME issuance complete; material adopted in memory and sealed to the capsule");
        return { status: "minted", expiresAt: result.expiresAt, lineageId };
      }
      if (result.status === "skipped") {
        throw new Error(`renewer refused to mint at boot: ${result.reason}`);
      }
      throw new Error(`unexpected renewal status at boot: ${result.status}`);
    } catch (error) {
      lastError = error;
      console.error(`[TLS bootstrap] mint attempt ${attempt}/${BOOTSTRAP_MAX_ATTEMPTS} failed: ${error.message}`);
      if (attempt < BOOTSTRAP_MAX_ATTEMPTS) {
        await sleep(BOOTSTRAP_RETRY_DELAY_MS);
      }
    }
  }

  // Mint failed (LE rate limit / DNS-TEE quorum outage). Serve the still-valid
  // capsule cert if there is one and keep retrying in the supervisor loop.
  if (capsule && capsuleValid) {
    adoptTlsMaterial(capsule, { origin: "carried_over" });
    console.error("[TLS bootstrap] mint failed; falling back to the still-valid sealed capsule cert and retrying renewal in the supervisor loop");
    return { status: "fallback_carried_over", expiresAt: capsuleExpiry.toISOString(), lineageId: capsule.lineageId ?? null };
  }
  throw lastError;
}

export async function runOnce({ now = new Date() } = {}) {
  if (inFlight) {
    console.log("[ACME] previous cycle still running; skipping this tick");
    return { status: "skipped_inflight" };
  }
  inFlight = true;
  try {
    let result = null;

    if (pendingRemint) {
      result = await runPendingRemint();
    } else {
      result = await maybeAdoptFresherCapsule({ now });
      if (!result) {
        result = await renewerDrivers.renewIfDue({ now });
        if (result.status === "renewed") {
          const lineageId = getCurrentTlsMaterial()?.lineageId ?? null;
          adoptTlsMaterial({ ...result.material, lineageId }, { origin: "minted_in_enclave" });
          await sealCurrentTlsMaterial("renewal");
          console.log("[ACME] renewal complete; secure context rotated in place and capsule re-sealed (no VM reset)");
        }
      }
    }

    if (result.status === "dry_run_complete") {
      console.log("[ACME] dry-run round-trip succeeded; nothing adopted or sealed");
    } else if (result.status === "not_due") {
      console.log("[ACME] certificate is still valid, no renewal needed");
    } else if (result.status === "skipped") {
      console.log(`[ACME] skipped: ${result.reason}`);
    }
    return result;
  } finally {
    inFlight = false;
  }
}

// Returns not_due if the IN-MEMORY cert is still well within its renewal
// window (the live secure context is the source of truth; there is no Secret
// Manager copy to consult).
export async function renewIfDue({ now = new Date() } = {}) {
  const skipReason = renewerSkipReason();
  if (skipReason) return { status: "skipped", reason: skipReason };

  const expiry = getCurrentCertExpiry();
  const remainingMs = expiry ? expiry.getTime() - now.getTime() : -Infinity;
  const renewalWindowMs = RENEWAL_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
  if (Number.isFinite(remainingMs) && remainingMs > renewalWindowMs) {
    return { status: "not_due", remainingMs, expiresAt: expiry?.toISOString() ?? null };
  }
  console.log("[ACME] certificate due for renewal; starting cycle");
  return runRenewal({ now });
}

// Unconditional order (no renewal-window check). Used by the boot bootstrap
// when no usable capsule exists and by lineage-driven re-mints (a genesis
// event must never inherit a carried-over cert). Same gates as renewIfDue.
export async function runForcedRenewal({ now = new Date() } = {}) {
  const skipReason = renewerSkipReason();
  if (skipReason) return { status: "skipped", reason: skipReason };
  return runRenewal({ now });
}

// Convergence guard for the shared capsule: a roll candidate (or a successor
// mid-handoff) serves the same hostname and shares one capsule. If OUR
// in-memory cert is due but a sibling already renewed and re-sealed, adopt
// that fresher material instead of spending another order against the shared
// LE duplicate-certificate quota.
async function maybeAdoptFresherCapsule({ now = new Date() } = {}) {
  if (renewerSkipReason()) return null;
  const expiry = getCurrentCertExpiry();
  const renewalWindowMs = RENEWAL_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
  const remainingMs = expiry ? expiry.getTime() - now.getTime() : -Infinity;
  if (remainingMs > renewalWindowMs) return null; // not due; nothing to converge

  let capsule = null;
  try {
    capsule = await unsealTlsMaterial();
  } catch {
    return null;
  }
  if (!capsule) return null;
  const capsuleExpiry = certExpiryFromPem(capsule.certPem);
  const capsuleRemainingMs = capsuleExpiry ? capsuleExpiry.getTime() - now.getTime() : -Infinity;
  if (capsuleRemainingMs <= renewalWindowMs || capsuleRemainingMs <= remainingMs) return null;

  adoptTlsMaterial(capsule, { origin: "carried_over" });
  console.log("[ACME] adopted a fresher cert from the shared sealed capsule (a sibling already renewed); no ACME order");
  return { status: "adopted_from_capsule", expiresAt: capsuleExpiry.toISOString() };
}

async function runPendingRemint() {
  const request = pendingRemint;
  console.log(`[ACME] running lineage-driven re-mint (${request.reason})`);
  const result = await renewerDrivers.runForcedRenewal();
  if (result.status === "renewed") {
    adoptTlsMaterial({ ...result.material, lineageId: request.lineageId ?? null }, { origin: "minted_in_enclave" });
    pendingRemint = null;
    await sealCurrentTlsMaterial(`re-mint (${request.reason})`);
    console.log("[ACME] lineage-driven re-mint complete; secure context rotated and capsule re-sealed under the new anchor");
    return { ...result, remint: request.reason };
  }
  if (result.status === "skipped") {
    // Renewer got disabled under us; keep the request so a re-enable retries.
    console.error(`[ACME] lineage-driven re-mint skipped: ${result.reason}; request stays pending`);
  }
  return result;
}

// Invoked (fire-and-forget) by governance-state.js when governance establishes
// a lineage: after /governance/genesis-bootstrap, after a successful
// /governance/activation-apply, and after a cold-start capsule restore.
// `lineageId` is the lineage anchor -- the genesis certificate's
// payloadDigest, stable across successor activations and restarts (the
// broker's KMS-backed governanceKeyId is shared across re-geneses, so the
// genesis cert digest is the unique per-lineage anchor).
//
//   genesis                            A genesis event ALWAYS requires a new
//                                      ACME cert: a new lineage must never
//                                      inherit a cert carried over from a
//                                      previous lineage's capsule. Material
//                                      this very enclave minted during this
//                                      boot is already a fresh cert, so it is
//                                      kept and only re-bound (and the capsule
//                                      re-sealed) under the new anchor.
//   successor_activation / lineage_restore
//                                      Lineage continuity: the carried-over
//                                      cert is KEPT. The capsule's recorded
//                                      anchor is verified against the
//                                      governance lineage; a mismatch (stale
//                                      capsule from a dead lineage) forces a
//                                      re-mint instead.
export async function reconcileTlsWithLineage({ lineageId = null, event }) {
  try {
    if (renewerSkipReason()) return { status: "skipped", reason: renewerSkipReason() };
    const material = getCurrentTlsMaterial();
    if (!material) return { status: "skipped", reason: "no TLS material adopted" };

    if (event === "genesis") {
      if (material.origin === "carried_over") {
        requestTlsRemint({ lineageId, reason: "genesis_requires_fresh_cert" });
        return { status: "remint_scheduled", reason: "genesis_requires_fresh_cert" };
      }
      setTlsLineageId(lineageId);
      await sealCurrentTlsMaterial("genesis lineage re-bind");
      return { status: "rebound", lineageId };
    }

    if (event === "successor_activation" || event === "lineage_restore") {
      if (material.lineageId && lineageId && material.lineageId !== lineageId) {
        requestTlsRemint({ lineageId, reason: "capsule_lineage_anchor_mismatch" });
        return { status: "remint_scheduled", reason: "capsule_lineage_anchor_mismatch" };
      }
      if (material.lineageId !== (lineageId ?? null)) {
        setTlsLineageId(lineageId);
        await sealCurrentTlsMaterial(`${event} lineage bind`);
        return { status: "rebound", lineageId };
      }
      return { status: "anchored", lineageId };
    }

    return { status: "skipped", reason: `unknown lineage event ${event}` };
  } catch (error) {
    console.error(`[ACME] TLS lineage reconcile (${event}) failed:`, error.message);
    return { status: "failed", error: error.message };
  }
}

function requestTlsRemint({ lineageId = null, reason }) {
  pendingRemint = { lineageId: lineageId ?? null, reason, requestedAt: new Date().toISOString() };
  // Kick immediately; runOnce()'s single-flight guard serializes this with the
  // periodic cycle, and pendingRemint survives failures so every later cycle
  // retries until the re-mint lands.
  runOnce().catch((error) => {
    console.error("[ACME] immediate re-mint cycle failed (will retry on supervisor cadence):", error.message);
  });
}

// Best-effort: a seal failure must never take down a TEE that holds perfectly
// good in-memory material. The failure is recorded for /health and the next
// successful cycle re-seals.
async function sealCurrentTlsMaterial(context) {
  const material = getCurrentTlsMaterial();
  if (!material) return;
  try {
    await sealTlsMaterial(material);
  } catch (error) {
    console.error(`[ACME] capsule seal failed after ${context} (serving from memory; will re-seal on a later cycle):`, error.message);
  }
}

async function runRenewal({ now = new Date() } = {}) {
  const accountKey = await loadOrCreateAcmeAccountKey();
  const client = new acme.Client({
    directoryUrl: ACME_DIRECTORY_URL,
    accountKey,
  });
  const [leafKeyBuffer, csrBuffer] = await acme.crypto.createCsr({ commonName: RENEWER_HOST_LABEL });

  let lastChallengeValue = null;
  const certPemBuffer = await client.auto({
    csr: csrBuffer,
    email: ACME_CONTACT_EMAIL,
    termsOfServiceAgreed: true,
    challengePriority: ["dns-01"],
    // acme-client's getChallengeKeyAuthorization() already returns the dns-01
    // record value for dns-01 challenges (base64url(sha256(token.thumbprint)));
    // it is passed here as keyAuthorization. Write it VERBATIM -- hashing it
    // again would double-hash so the served TXT never matches what Boulder
    // expects.
    skipChallengeVerification: true,
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      if (challenge.type !== "dns-01") return;
      lastChallengeValue = keyAuthorization;
      // submitRenewerChange resolves only when all four slots return APPROVE,
      // and each slot writes + reloads NSD before returning APPROVE, so every
      // authoritative slot is serving the TXT once this resolves. A short settle
      // window then covers NSD reload-to-serving + validator query timing; the
      // supervisor retries the whole order if Boulder validation still fails.
      await submitRenewerChange({ op: "add", value: lastChallengeValue });
      await sleep(RENEWER_POST_APPROVE_SETTLE_MS);
    },
    challengeRemoveFn: async (authz, challenge) => {
      if (challenge.type !== "dns-01") return;
      if (!lastChallengeValue) return;
      try {
        await submitRenewerChange({ op: "remove", value: lastChallengeValue });
      } catch (error) {
        console.error("[ACME] failed to remove _acme-challenge TXT:", error.message);
      }
    },
  });

  const certPem = certPemBuffer.toString();
  const keyPem = leafKeyBuffer.toString();

  if (isDryRun()) {
    return {
      status: "dry_run_complete",
      certPemPreview: certPem.split("\n").slice(0, 2).join("\n"),
    };
  }

  // The fresh key+cert are returned IN MEMORY only. The caller adopts them
  // into the live secure context and re-seals the attestation-gated capsule;
  // plaintext never leaves this process.
  return {
    status: "renewed",
    material: {
      keyPem,
      certPem,
      mintedAt: now.toISOString(),
    },
    expiresAt: certExpiryFromPem(certPem)?.toISOString() ?? null,
  };
}

async function submitRenewerChange({ op, value }) {
  const change = {
    op,
    name: `_acme-challenge.${RENEWER_HOST_LABEL}.`,
    type: "TXT",
    ttl: RENEWER_TXT_TTL,
    values: [value],
  };
  const envelope = await activeEnvelopeBuilder()({ change, route: RENEWER_ROUTE });

  const failures = [];
  await Promise.all(DNS_TEE_RENEWER_URLS.map(async (baseUrl) => {
    const url = `${baseUrl.replace(/\/+$/, "")}${RENEWER_ROUTE}`;
    let response;
    try {
      response = await dnsTeeFetcher(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ envelope }),
        signal: AbortSignal.timeout(30_000),
      });
    } catch (error) {
      failures.push({ url, error: error.message });
      return;
    }
    if (!response.ok) {
      const text = await safeReadResponseText(response);
      failures.push({ url, status: response.status, error: text });
      return;
    }
    let json;
    try {
      json = await response.json();
    } catch (error) {
      failures.push({ url, error: `invalid json: ${error.message}` });
      return;
    }
    if (json.decision !== "APPROVE") {
      failures.push({ url, error: `non-APPROVE decision: ${json.decision}` });
    }
  }));
  if (failures.length > 0) {
    throw new Error(`renewer zone change failed against ${failures.length}/${DNS_TEE_RENEWER_URLS.length} DNS-TEE peers: ${JSON.stringify(failures)}`);
  }
}

async function safeReadResponseText(response) {
  try {
    return (await response.text()).slice(0, 512);
  } catch {
    return "<unreadable response body>";
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

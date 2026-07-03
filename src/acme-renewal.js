// Ephemeral in-enclave TLS: in-TEE ACME DNS-01 renewer + supervisor
// (auth-broker-tee).
//
// Owns the lifecycle of this TEE's TLS material for `oauth-tee.femled.ai`.
// There is NO at-rest form of the key: nothing is sealed to KMS or written to
// GCS/Secret Manager, so a GCP project/org IAM owner has nothing to decrypt.
// The trade-off is that a cold boot has no cert to carry over and must mint a
// fresh one, which consumes a Let's Encrypt issuance.
//
//   boot        bootstrapTls(): always mints a fresh cert in-enclave via ACME
//               DNS-01 before the HTTPS listener binds. A non-secret mint
//               ledger (tls-mint-log.js) records mint timestamps so a reboot
//               loop fails fast instead of burning the LE weekly limit.
//   renewal     runOnce() on a 24h cadence: when the in-memory cert is inside
//               its renewal window, orders a fresh cert and rotates the live
//               listener in place via server.setSecureContext() (no VM reset,
//               nothing persisted).
//
// The leaf private key is generated inside the TEE and NEVER persisted. DNS-01
// rides authoritative-dns-tee's external-TEE-renewer trust path for the
// `_acme-challenge.oauth-tee.femled.ai` TXT writes.

import acme from "acme-client";
import { loadOrCreateAcmeAccountKey } from "./acme-account.js";
import { buildRenewerEnvelope, RENEWER_HOST } from "./renewer-governance-signer.js";
import {
  adoptTlsMaterial,
  getCurrentCertExpiry,
  certExpiryFromPem,
  getTlsMaterialStatus,
} from "./tls-material.js";
import {
  assertMintWithinWeeklyBudget,
  recordSuccessfulMint,
  getMintLogStatus,
} from "./tls-mint-log.js";

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

// Boot-time bootstrap retries: several ACME order attempts per boot before
// giving up (and letting the VM crashloop into a fresh boot).
const BOOTSTRAP_MAX_ATTEMPTS = Number(process.env.ACME_BOOTSTRAP_MAX_ATTEMPTS || 6);
const BOOTSTRAP_RETRY_DELAY_MS = Number(process.env.ACME_BOOTSTRAP_RETRY_DELAY_MS || 20_000);

let inFlight = false;
let timer = null;

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
  inFlight = false;
}

export function getTlsRuntimeStatus() {
  return {
    schema: "femled.auth_broker_tee.tls_runtime.v1",
    material: getTlsMaterialStatus(),
    mintLog: getMintLogStatus(),
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
// binds; the adopted material lives only in process memory and is never
// persisted. Because there is no capsule to carry over, boot ALWAYS mints.
//
// Dry-run must NOT issue at boot: runRenewal() performs a full real ACME order
// against the LE production directory and only checks the dry-run flag
// afterward, returning without material. Issuing in dry-run at boot would leave
// TLS unadopted and crashloop the VM while spending real LE orders.
export async function bootstrapTls({ now = new Date() } = {}) {
  const skipReason = renewerSkipReason();
  if (skipReason) {
    throw new Error(`in-enclave TLS minting is unavailable: ${skipReason}`);
  }
  if (isDryRun()) {
    throw new Error("ACME_RENEWER_DRY_RUN is set; the boot path cannot mint an adoptable cert");
  }
  // Fail fast (no wasted LE order) if a reboot loop has already exhausted the
  // weekly issuance budget. This throws before any ACME attempt.
  await assertMintWithinWeeklyBudget({ now });

  let lastError = null;
  for (let attempt = 1; attempt <= BOOTSTRAP_MAX_ATTEMPTS; attempt += 1) {
    try {
      const result = await renewerDrivers.runForcedRenewal({ now });
      if (result.status === "renewed") {
        adoptTlsMaterial(result.material);
        await recordSuccessfulMint({ now });
        console.log("[TLS bootstrap] minted a fresh in-enclave cert (ephemeral; nothing persisted)");
        return { status: "minted", expiresAt: result.expiresAt };
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

  // No capsule fallback exists in the ephemeral model: boot fails and the VM
  // restarts into a fresh attempt (the mint ledger prevents that loop from
  // burning the LE weekly budget).
  throw lastError;
}

export async function runOnce({ now = new Date() } = {}) {
  if (inFlight) {
    console.log("[ACME] previous cycle still running; skipping this tick");
    return { status: "skipped_inflight" };
  }
  inFlight = true;
  try {
    const result = await renewerDrivers.renewIfDue({ now });
    if (result.status === "renewed") {
      adoptTlsMaterial(result.material);
      await recordSuccessfulMint({ now });
      console.log("[ACME] renewal complete; secure context rotated in place (no VM reset, nothing persisted)");
    } else if (result.status === "dry_run_complete") {
      console.log("[ACME] dry-run round-trip succeeded; nothing adopted");
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
// window (the live secure context is the only source of truth; there is no
// persisted copy to consult).
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

// Unconditional order (no renewal-window check). Used by the boot bootstrap.
// Same gates as renewIfDue.
export async function runForcedRenewal({ now = new Date() } = {}) {
  const skipReason = renewerSkipReason();
  if (skipReason) return { status: "skipped", reason: skipReason };
  return runRenewal({ now });
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

  // The fresh key+cert are returned IN MEMORY only. The caller adopts them into
  // the live secure context; plaintext never leaves this process and is never
  // sealed anywhere.
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

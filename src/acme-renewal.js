// In-TEE ACME DNS-01 renewer (auth-broker-tee port).
//
// Drives renewal of the public TLS cert for `oauth-tee.femled.ai`. Replaces
// the previous Cloudflare REST integration with authoritative-dns-tee's
// external-TEE-renewer trust path for the
// `_acme-challenge.oauth-tee.femled.ai` TXT writes. The leaf private key is
// generated inside the TEE and never leaves it; on success we write new
// versions of the existing TLS Secret Manager secrets and reset this VM via
// compute.instances.reset (replacing the previous in-process
// `server.setSecureContext()` hot reload, aligning the reload contract with
// coach-email-tee).
//
// Pre-cutover bridge: while DNS authority is still on Cloudflare, leave
// ACME_RENEWER_ENABLED=false (the default) and keep the previous Cloudflare
// path running by reverting the metadata flag. Once authoritative-dns-tee is
// authoritative *and* the new path has succeeded once in dry-run, flip
// ACME_RENEWER_ENABLED=true.

import acme from "acme-client";
import {
  isCertExpiringSoon,
  loadTlsCredentials,
  persistTlsCredentials,
} from "./tls.js";
import { loadOrCreateAcmeAccountKey } from "./acme-account.js";
import { buildRenewerEnvelope, RENEWER_HOST } from "./renewer-governance-signer.js";
import { resetComputeInstance } from "./gcp-auth.js";

const RENEWER_ROUTE = "/governance/routine-zone-change-renewer";
const RENEWER_TXT_TTL = 60;
const RENEWAL_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const RENEWAL_THRESHOLD_DAYS = 30;
const ACME_DIRECTORY_URL = process.env.ACME_DIRECTORY_URL || acme.directory.letsencrypt.production;
const ACME_CONTACT_EMAIL = process.env.ACME_CONTACT_EMAIL || "engineering@femled.ai";
const ACME_RENEWER_ENABLED = process.env.ACME_RENEWER_ENABLED === "true";
const ACME_RENEWER_DRY_RUN = process.env.ACME_RENEWER_DRY_RUN === "true";
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
const SELF_VM_NAME = process.env.SELF_VM_NAME || "auth-broker-tee";
const SELF_VM_ZONE = process.env.SELF_VM_ZONE || "us-west1-b";
const RENEWER_HOST_LABEL = RENEWER_HOST.replace(/\.$/, "");

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

let resetCaller = (args) => resetComputeInstance(args);
export function setComputeResetterForTests(fn) {
  resetCaller = fn || ((args) => resetComputeInstance(args));
}

export function startRenewalLoop() {
  if (timer) return;
  if (!ACME_RENEWER_ENABLED) {
    console.log("[ACME] ACME_RENEWER_ENABLED is false; renewer supervisor not started");
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

export async function runOnce() {
  if (inFlight) {
    console.log("[ACME] previous cycle still running; skipping this tick");
    return { status: "skipped_inflight" };
  }
  inFlight = true;
  try {
    return await checkAndRenew();
  } finally {
    inFlight = false;
  }
}

async function checkAndRenew() {
  let cert = null;
  try {
    const credentials = await loadTlsCredentials();
    cert = credentials.cert;
  } catch (error) {
    if (!/TLS credentials not configured/i.test(error.message)) {
      console.error("[ACME] failed to load existing TLS credentials:", error.message);
      throw error;
    }
    console.log("[ACME] no existing cert found, requesting initial certificate");
  }
  if (cert && !isCertExpiringSoon(cert, RENEWAL_THRESHOLD_DAYS)) {
    console.log("[ACME] certificate is still valid, no renewal needed");
    return { status: "not_due" };
  }
  console.log("[ACME] certificate due for renewal; starting cycle");
  return runRenewal();
}

async function runRenewal() {
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

  if (ACME_RENEWER_DRY_RUN) {
    return {
      status: "dry_run_complete",
      certPemPreview: certPem.split("\n").slice(0, 2).join("\n"),
    };
  }

  await persistTlsCredentials(certPem, keyPem);

  console.log("[ACME] renewal complete; resetting VM to pick up new TLS material");
  try {
    await resetCaller({ zone: SELF_VM_ZONE, instanceName: SELF_VM_NAME });
  } catch (error) {
    console.error("[ACME] compute.instances.reset failed; new TLS material is sealed but VM did not restart:", error.message);
  }

  return { status: "renewed" };
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

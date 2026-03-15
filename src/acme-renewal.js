import acme from "acme-client";
import {
  loadTlsCredentials,
  isCertExpiringSoon,
  persistTlsCredentials,
} from "./tls.js";

const DOMAIN = "oauth-tee.femled.ai";
const CLOUDFLARE_DNS_TOKEN = process.env.CLOUDFLARE_DNS_TOKEN;
const CLOUDFLARE_ZONE_ID = process.env.CLOUDFLARE_ZONE_ID || "b9391961e5c7b2f5c1ab99cfc958f613";
const RENEWAL_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const RENEWAL_THRESHOLD_DAYS = 30;

export async function startRenewalLoop(server) {
  if (!CLOUDFLARE_DNS_TOKEN) {
    console.log("[ACME] CLOUDFLARE_DNS_TOKEN not set, automatic renewal disabled");
    return;
  }

  await checkAndRenew(server);

  setInterval(() => {
    checkAndRenew(server).catch((err) => {
      console.error("[ACME] Renewal check failed:", err.message);
    });
  }, RENEWAL_CHECK_INTERVAL_MS);
}

async function checkAndRenew(server) {
  try {
    const { cert } = await loadTlsCredentials();

    if (!isCertExpiringSoon(cert, RENEWAL_THRESHOLD_DAYS)) {
      console.log("[ACME] Certificate is still valid, no renewal needed");
      return;
    }

    console.log("[ACME] Certificate expiring soon, starting renewal");
    await renewCertificate(server);
  } catch (err) {
    if (err.message.includes("TLS credentials not configured")) {
      console.log("[ACME] No existing cert found, requesting initial certificate");
      await renewCertificate(server);
    } else {
      throw err;
    }
  }
}

async function renewCertificate(server) {
  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt.production,
    accountKey: await acme.crypto.createPrivateKey(),
  });

  const [certificateKey, certificateCsr] = await acme.crypto.createCsr({
    commonName: DOMAIN,
  });

  const cert = await client.auto({
    csr: certificateCsr,
    email: "engineering@femled.ai",
    termsOfServiceAgreed: true,
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      if (challenge.type !== "dns-01") return;
      const dnsRecord = `_acme-challenge.${authz.identifier.value}`;
      const txtValue = keyAuthorization;
      await createCloudflareTxtRecord(dnsRecord, txtValue);
      await waitForDnsPropagation(60000);
    },
    challengeRemoveFn: async (authz, challenge) => {
      if (challenge.type !== "dns-01") return;
      const dnsRecord = `_acme-challenge.${authz.identifier.value}`;
      await deleteCloudflareTxtRecord(dnsRecord);
    },
    challengePriority: ["dns-01"],
  });

  const keyPem = certificateKey.toString();
  const certPem = cert.toString();

  console.log("[ACME] Certificate obtained, persisting to Secret Manager");
  await persistTlsCredentials(certPem, keyPem);

  console.log("[ACME] Hot-reloading TLS context");
  server.setSecureContext({ key: keyPem, cert: certPem });

  console.log("[ACME] Renewal complete");
}

// ---------------------------------------------------------------------------
// Cloudflare DNS API helpers
// ---------------------------------------------------------------------------

let acmeTxtRecordId = null;

async function createCloudflareTxtRecord(name, content) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${CLOUDFLARE_DNS_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: "TXT",
        name,
        content,
        ttl: 120,
      }),
    }
  );

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Cloudflare DNS create failed (${response.status}): ${err}`);
  }

  const data = await response.json();
  acmeTxtRecordId = data.result.id;
  console.log(`[ACME] Created TXT record: ${name}`);
}

async function deleteCloudflareTxtRecord(name) {
  if (!acmeTxtRecordId) {
    const records = await listCloudflareTxtRecords(name);
    if (records.length === 0) return;
    for (const record of records) {
      await deleteRecordById(record.id);
    }
    return;
  }

  await deleteRecordById(acmeTxtRecordId);
  acmeTxtRecordId = null;
}

async function deleteRecordById(recordId) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${recordId}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${CLOUDFLARE_DNS_TOKEN}` },
    }
  );

  if (!response.ok) {
    console.error(`[ACME] Failed to delete DNS record ${recordId}:`, response.status);
  } else {
    console.log(`[ACME] Deleted TXT record ${recordId}`);
  }
}

async function listCloudflareTxtRecords(name) {
  const params = new URLSearchParams({ type: "TXT", name });
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?${params}`,
    {
      headers: { Authorization: `Bearer ${CLOUDFLARE_DNS_TOKEN}` },
    }
  );

  if (!response.ok) return [];
  const data = await response.json();
  return data.result || [];
}

function waitForDnsPropagation(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

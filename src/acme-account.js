// ACME account key loader/sealer (auth-broker-tee port).
//
// The previous renewer at src/acme-renewal.js generated a fresh ACME account
// key on every cycle. Persisting the key avoids LE rate-limit pressure and
// produces a stable renewer identity in LE's logs. Compromise is bounded by
// the DNS-01 governance gate (image-baked allow-list + scope predicate +
// First-Principles APPROVE on the DNS TEE side).

import acme from "acme-client";
import { fetchSecretByName, writeSecretValue } from "./gcp-auth.js";

// Hardcoded so the .compliance/check-secrets.mjs static-literal rule passes.
// IAM access is image-digest-pinned via WIF (terraform/acme-renewer.tf).
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN (RSA |EC )?PRIVATE KEY-----/;
const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID;

let cachedAccountKey = null;

export async function loadOrCreateAcmeAccountKey() {
  if (cachedAccountKey) return cachedAccountKey;
  let pem = null;
  try {
    const value = await fetchSecretByName("auth-broker-tee-acme-account-key");
    if (value && PEM_PRIVATE_KEY_PATTERN.test(value)) pem = value.trim();
  } catch (error) {
    if (!/no.*version|not.*found|404|400/i.test(error.message)) throw error;
  }
  if (!pem) {
    const generated = await acme.crypto.createPrivateKey();
    pem = generated.toString("utf8");
    await writeSecretValue(`projects/${GCP_PROJECT_ID}/secrets/auth-broker-tee-acme-account-key`, pem);
  }
  cachedAccountKey = Buffer.from(pem, "utf8");
  return cachedAccountKey;
}

export function resetAcmeAccountKeyCacheForTests() {
  cachedAccountKey = null;
}

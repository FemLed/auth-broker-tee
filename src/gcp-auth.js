import crypto from "node:crypto";
import fs from "node:fs";
import { recordWifTokenExchange } from "./governance-monitor.js";

const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID;
const GCP_PROJECT_NUMBER = process.env.GCP_PROJECT_NUMBER;
const WIF_POOL_ID = "auth-broker-tee-pool";
const WIF_PROVIDER_ID = "attestation-verifier";
const ATTESTATION_TOKEN_PATH =
  "/run/container_launcher/attestation_verifier_claims_token";

let wifTokenCache = null;

// Test-only hook to pre-prime the WIF token cache so unit tests that exercise
// downstream KMS/Secret-Manager/GCS code paths do not need a live Confidential
// Space attestation file at /run/container_launcher/.... Production code never
// calls this; the attestation file is the only token source on a real VM.
export function primeWifTokenForTests(token, ttlMs = 60 * 60 * 1000) {
  if (!token) {
    wifTokenCache = null;
    return;
  }
  wifTokenCache = { token, expiresAt: Date.now() + ttlMs };
}

/**
 * Obtains a federated access token by exchanging the Confidential Space
 * attestation token via Workload Identity Federation (WIF).
 *
 * The attestation token is written to a well-known path by the Confidential
 * Space launcher and is signed by Google Cloud Attestation. The STS exchange
 * returns a short-lived access token scoped to the federated identity, which
 * only has access to secrets whose IAM bindings match the container image
 * digest in the attestation token.
 */
export async function getWifAccessToken() {
  const now = Date.now();
  if (wifTokenCache && wifTokenCache.expiresAt > now) {
    return wifTokenCache.token;
  }

  try {
    const subjectToken = fs.readFileSync(ATTESTATION_TOKEN_PATH, "utf8").trim();

    const audience = `//iam.googleapis.com/projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_ID}/providers/${WIF_PROVIDER_ID}`;

    const response = await fetch("https://sts.googleapis.com/v1/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        subject_token: subjectToken,
        audience,
        scope: "https://www.googleapis.com/auth/cloud-platform",
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`WIF STS token exchange failed (${response.status}): ${errText}`);
    }

    const data = await response.json();
    recordWifTokenExchange({ status: "success" });
    wifTokenCache = {
      token: data.access_token,
      expiresAt: now + (data.expires_in - 120) * 1000,
    };
    return data.access_token;
  } catch (error) {
    recordWifTokenExchange({ status: "failed", reason: error.message });
    throw error;
  }
}

export function getLauncherAttestationClaims() {
  const subjectToken = fs.readFileSync(ATTESTATION_TOKEN_PATH, "utf8").trim();
  const parts = subjectToken.split(".");
  if (parts.length !== 3) {
    throw new Error("Launcher attestation token is not a JWT");
  }
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

export function getAttestedImageDigest() {
  return getLauncherAttestationClaims().submods?.container?.image_digest || null;
}

export function getAttestedImageReference() {
  return getLauncherAttestationClaims().submods?.container?.image_reference || null;
}

/**
 * Obtains a standard GCP access token from the metadata server.
 * Used for Firestore access (which uses the VM service account, not WIF).
 */
const METADATA_TOKEN_URL =
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
let metadataTokenCache = null;

export async function getMetadataAccessToken() {
  const now = Date.now();
  if (metadataTokenCache && metadataTokenCache.expiresAt > now) {
    return metadataTokenCache.token;
  }

  const response = await fetch(METADATA_TOKEN_URL, {
    headers: { "Metadata-Flavor": "Google" },
  });

  if (!response.ok) {
    console.error("Metadata token fetch failed:", response.status);
    return null;
  }

  const data = await response.json();
  metadataTokenCache = {
    token: data.access_token,
    expiresAt: now + (data.expires_in - 60) * 1000,
  };
  return data.access_token;
}

export async function fetchSecretValue(secretResourceName) {
  const accessToken = await getWifAccessToken();

  const url = `https://secretmanager.googleapis.com/v1/${secretResourceName}:access`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(
      `Secret Manager access failed (${response.status}): ${errText}`
    );
  }

  const data = await response.json();
  return Buffer.from(data.payload.data, "base64").toString("utf8");
}

export async function fetchSecretByName(secretName) {
  return fetchSecretValue(
    `projects/${GCP_PROJECT_ID}/secrets/${secretName}/versions/latest`
  );
}

export async function writeSecretValue(secretResourceName, value) {
  const accessToken = await getWifAccessToken();

  const url = `https://secretmanager.googleapis.com/v1/${secretResourceName}:addVersion`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      payload: { data: Buffer.from(value).toString("base64") },
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(
      `Secret Manager write failed (${response.status}): ${errText}`
    );
  }

  return response.json();
}

export function getProjectId() {
  return process.env.GCP_PROJECT_ID || GCP_PROJECT_ID;
}

// Cloud KMS asymmetric sign for the renewer governance signer key. Returns
// the raw signature bytes (DER-encoded ECDSA for EC_SIGN_P256_SHA256), which
// is what authoritative-dns-tee's verifier expects via Node `crypto.verify`.
export async function kmsAsymmetricSign(keyVersionResource, dataToSign) {
  const accessToken = await getWifAccessToken();
  const digest = crypto.createHash("sha256").update(dataToSign).digest("base64");
  const url = `https://cloudkms.googleapis.com/v1/${keyVersionResource}:asymmetricSign`;
  const response = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ digest: { sha256: digest } }),
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    throw new Error(`Cloud KMS asymmetricSign failed (${response.status}): ${await response.text()}`);
  }
  const data = await response.json();
  if (typeof data.signature !== "string") throw new Error("Cloud KMS asymmetricSign returned no signature");
  return Buffer.from(data.signature, "base64");
}

export async function kmsGetPublicKey(keyVersionResource) {
  const accessToken = await getWifAccessToken();
  const url = `https://cloudkms.googleapis.com/v1/${keyVersionResource}/publicKey`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) {
    throw new Error(`Cloud KMS getPublicKey failed (${response.status}): ${await response.text()}`);
  }
  const data = await response.json();
  if (typeof data.pem !== "string") throw new Error("Cloud KMS getPublicKey returned no pem");
  return data.pem;
}

// Reset this VM via the Compute Engine API. Used at the end of a successful
// renewal to restart the TEE so it picks up the freshly-seeded TLS Secret
// Manager versions on next boot. The IAM role is scoped to a single-instance
// condition in Terraform so this principal can only reset its own VM.
export async function resetComputeInstance({ project = GCP_PROJECT_ID, zone, instanceName }) {
  const accessToken = await getWifAccessToken();
  const url = `https://compute.googleapis.com/compute/v1/projects/${project}/zones/${zone}/instances/${instanceName}/reset`;
  const response = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) {
    throw new Error(`compute.instances.reset failed for ${instanceName} (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

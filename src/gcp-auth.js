import fs from "node:fs";

const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID;
const GCP_PROJECT_NUMBER = process.env.GCP_PROJECT_NUMBER;
const WIF_POOL_ID = "auth-broker-tee-pool";
const WIF_PROVIDER_ID = "attestation-verifier";
const ATTESTATION_TOKEN_PATH =
  "/run/container_launcher/attestation_verifier_claims_token";

let wifTokenCache = null;

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
  wifTokenCache = {
    token: data.access_token,
    expiresAt: now + (data.expires_in - 120) * 1000,
  };
  return data.access_token;
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
  return GCP_PROJECT_ID;
}

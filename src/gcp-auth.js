import crypto from "node:crypto";

const GCP_SA_KEY = process.env.GCP_SA_KEY;
const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID;

let gcpTokenCache = null;

export async function getGcpAccessToken(scope) {
  const now = Date.now();
  const cacheKey = scope || "default";
  if (gcpTokenCache && gcpTokenCache.scope === cacheKey && gcpTokenCache.expiresAt > now) {
    return gcpTokenCache.token;
  }

  const saKey = JSON.parse(GCP_SA_KEY);
  const iat = Math.floor(now / 1000);
  const exp = iat + 3600;

  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: saKey.client_email,
    sub: saKey.client_email,
    aud: "https://oauth2.googleapis.com/token",
    iat,
    exp,
    scope: scope || "https://www.googleapis.com/auth/datastore",
  };

  const jwt = signRsaJwt(header, payload, saKey.private_key);

  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  if (!tokenResponse.ok) {
    const errorText = await tokenResponse.text();
    console.error("GCP token exchange failed:", tokenResponse.status);
    return null;
  }

  const tokenData = await tokenResponse.json();
  gcpTokenCache = {
    token: tokenData.access_token,
    scope: cacheKey,
    expiresAt: now + 3500 * 1000,
  };
  return tokenData.access_token;
}

export async function fetchSecretValue(secretResourceName) {
  const accessToken = await getGcpAccessToken(
    "https://www.googleapis.com/auth/cloud-platform"
  );
  if (!accessToken) {
    throw new Error("Failed to get GCP access token for Secret Manager");
  }

  const url = `https://secretmanager.googleapis.com/v1/${secretResourceName}:access`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Secret Manager access failed (${response.status}): ${errText}`);
  }

  const data = await response.json();
  return Buffer.from(data.payload.data, "base64").toString("utf8");
}

export function getProjectId() {
  return GCP_PROJECT_ID;
}

function signRsaJwt(header, payload, privateKeyPem) {
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const unsignedToken = `${headerB64}.${payloadB64}`;

  const sign = crypto.createSign("RSA-SHA256");
  sign.update(unsignedToken);
  const signature = sign.sign(privateKeyPem);
  const signatureB64 = base64urlFromBuffer(signature);

  return `${unsignedToken}.${signatureB64}`;
}

function base64urlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlFromBuffer(buf) {
  return buf
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

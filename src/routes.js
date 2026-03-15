import crypto from "node:crypto";
import { getMetadataAccessToken, getProjectId } from "./gcp-auth.js";
import { jsonResponse, textResponse, redirectResponse } from "./http-helpers.js";

const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const FIRESTORE_COLLECTION = "couples";

const env = (k) => process.env[k];

const routeCache = new Map();

// ---------------------------------------------------------------------------
// GET /login
// ---------------------------------------------------------------------------
export async function handleLogin(url, req, res) {
  const tenant = url.searchParams.get("tenant");
  if (!tenant) {
    return jsonResponse(res, 400, { error: "Missing tenant parameter" });
  }

  const state = signState(tenant, env("HMAC_SECRET"));

  const params = new URLSearchParams({
    client_id: env("GOOGLE_CLIENT_ID"),
    redirect_uri: env("REDIRECT_URI"),
    response_type: "code",
    scope: env("GOOGLE_SCOPES"),
    access_type: "offline",
    prompt: "consent",
    state,
  });

  return redirectResponse(res, `${GOOGLE_AUTH_ENDPOINT}?${params.toString()}`);
}

// ---------------------------------------------------------------------------
// GET /callback
// ---------------------------------------------------------------------------
export async function handleCallback(url, req, res) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    console.error("OAuth error:", error);
    return textResponse(res, 400, `OAuth error: ${error}`);
  }

  if (!code || !state) {
    return textResponse(res, 400, "Missing code or state");
  }

  const tenant = verifyState(state, env("HMAC_SECRET"));
  if (!tenant) {
    return textResponse(res, 403, "Invalid or tampered state parameter");
  }

  const tokenResponse = await fetch(GOOGLE_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env("GOOGLE_CLIENT_ID"),
      client_secret: env("GOOGLE_CLIENT_SECRET"),
      redirect_uri: env("REDIRECT_URI"),
      grant_type: "authorization_code",
    }),
  });

  if (!tokenResponse.ok) {
    console.error("Token exchange failed:", tokenResponse.status);
    return textResponse(res, 502, "Token exchange failed");
  }

  const tokens = await tokenResponse.json();

  const apiHost = await getApiUrlForTenant(tenant);
  if (!apiHost) {
    console.error("Could not resolve tenant:", tenant);
    return textResponse(res, 404, "Tenant not found");
  }

  const depositUrl = `https://${apiHost}/api/google-auth/deposit-tokens`;
  const depositPayload = {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    id_token: tokens.id_token,
    expiry_date: tokens.expires_in
      ? Date.now() + tokens.expires_in * 1000
      : null,
    scope: tokens.scope,
    token_type: tokens.token_type,
  };

  const depositResponse = await fetch(depositUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Broker-Api-Key": env("BROKER_API_KEY"),
    },
    body: JSON.stringify(depositPayload),
  });

  if (!depositResponse.ok) {
    console.error("Token deposit failed:", depositResponse.status);
    return textResponse(res, 502, "Failed to deposit tokens with tenant backend");
  }

  const redirectTarget = `https://app-${tenant}.femled.ai/chat?auth_success=true&id_token=${encodeURIComponent(tokens.id_token)}`;
  return redirectResponse(res, redirectTarget);
}

// ---------------------------------------------------------------------------
// POST /refresh
// ---------------------------------------------------------------------------
export async function handleRefresh(req, res) {
  if (req.method !== "POST") {
    return textResponse(res, 405, "Method not allowed");
  }

  const apiKey = req.headers["x-broker-api-key"];
  if (apiKey !== env("BROKER_API_KEY")) {
    return jsonResponse(res, 401, { error: "Unauthorized" });
  }

  const body = await readJsonBody(req);
  if (!body) {
    return jsonResponse(res, 400, { error: "Invalid JSON body" });
  }

  const { refresh_token } = body;
  if (!refresh_token) {
    return jsonResponse(res, 400, { error: "Missing refresh_token" });
  }

  const tokenResponse = await fetch(GOOGLE_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env("GOOGLE_CLIENT_ID"),
      client_secret: env("GOOGLE_CLIENT_SECRET"),
      refresh_token,
      grant_type: "refresh_token",
    }),
  });

  if (!tokenResponse.ok) {
    console.error("Token refresh failed:", tokenResponse.status);
    const status =
      tokenResponse.status === 400 || tokenResponse.status === 401
        ? tokenResponse.status
        : 502;
    return jsonResponse(res, status, { error: "Token refresh failed" });
  }

  const tokens = await tokenResponse.json();

  return jsonResponse(res, 200, {
    access_token: tokens.access_token,
    id_token: tokens.id_token,
    expiry_date: tokens.expires_in
      ? Date.now() + tokens.expires_in * 1000
      : null,
    refresh_token: tokens.refresh_token || null,
  });
}

// ---------------------------------------------------------------------------
// Firestore route lookup
// ---------------------------------------------------------------------------
async function getApiUrlForTenant(uuid) {
  const cacheTtl = 2592000 * 1000; // 30 days
  const now = Date.now();

  const cached = routeCache.get(uuid);
  if (cached && cached.expiresAt > now) {
    return cached.apiUrl;
  }

  const accessToken = await getMetadataAccessToken();
  if (!accessToken) {
    console.error("Failed to get GCP access token for Firestore lookup");
    return null;
  }

  const projectId = getProjectId();
  const firestoreUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${FIRESTORE_COLLECTION}/${uuid}`;

  const response = await fetch(firestoreUrl, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    if (response.status === 404) {
      console.error(`Tenant ${uuid} not found in Firestore`);
    } else {
      console.error("Firestore error:", response.status);
    }
    return null;
  }

  const doc = await response.json();
  const apiUrl = doc.fields?.api_url?.stringValue || "";

  if (!apiUrl) {
    console.error(`Tenant ${uuid} has no api_url in Firestore`);
    return null;
  }

  routeCache.set(uuid, { apiUrl, expiresAt: now + cacheTtl });
  return apiUrl;
}

// ---------------------------------------------------------------------------
// HMAC state signing/verification
// ---------------------------------------------------------------------------
function signState(tenant, secret) {
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(tenant);
  const sig = hmac.digest("hex");
  return `${tenant}.${sig}`;
}

function verifyState(state, secret) {
  const dotIndex = state.lastIndexOf(".");
  if (dotIndex === -1) return null;

  const data = state.substring(0, dotIndex);
  const sig = state.substring(dotIndex + 1);

  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(data);
  const expected = hmac.digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return null;
  }
  return data;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function readJsonBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        resolve(null);
      }
    });
    req.on("error", () => resolve(null));
  });
}

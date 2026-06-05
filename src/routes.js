import crypto from "node:crypto";
import { sha256Digest } from "./canonical-json.js";
import { getMetadataAccessToken, getProjectId } from "./gcp-auth.js";
import { jsonResponse, textResponse, redirectResponse } from "./http-helpers.js";
import { sendSilentPush, sendAlertPush } from "./apns.js";
import {
  buildRouteProofHeaders,
  getDeployWebhookRouteForRepo,
  getTenantApiRoute,
} from "./route-registry.js";
import {
  recordDeployWebhook,
  recordRouteProof,
  recordTenantRouteLookup,
  recordTokenDeposit,
} from "./governance-monitor.js";

const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GITHUB_API_BASE = "https://api.github.com";
const DEFAULT_POST_LOGIN_PATH = "/chat";
const ALLOWED_NATIVE_RETURN_TO = new Set(["femled-coach://oauth"]);

const env = (k) => process.env[k];

let githubAppJwtCache = null;

// ---------------------------------------------------------------------------
// GET /login
// ---------------------------------------------------------------------------
export async function handleLogin(url, req, res) {
  const tenant = url.searchParams.get("tenant");
  if (!tenant) {
    return jsonResponse(res, 400, { error: "Missing tenant parameter" });
  }

  const requestedReturnTo = url.searchParams.get("return_to");
  const returnTo = normalizeReturnTo(requestedReturnTo);
  if (requestedReturnTo && !returnTo) {
    return jsonResponse(res, 400, { error: "Invalid return_to parameter" });
  }

  const state = signState({ tenant, returnTo }, env("HMAC_SECRET"));

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

  const statePayload = verifyState(state, env("HMAC_SECRET"));
  if (!statePayload) {
    return textResponse(res, 403, "Invalid or tampered state parameter");
  }
  const { tenant, returnTo } = statePayload;

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

  const tenantRoute = getTenantApiRouteForTenant(tenant);
  if (!tenantRoute) {
    console.error("Could not resolve tenant:", tenant);
    return textResponse(res, 404, "Tenant not found");
  }

  const apiHost = tenantRoute.payload.apiHost;
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

  let routeProofHeaders;
  try {
    routeProofHeaders = buildPrivacySafeRouteProofHeaders(tenantRoute);
  } catch {
    return textResponse(res, 502, "Failed to build tenant route proof");
  }

  let depositResponse;
  try {
    depositResponse = await fetch(depositUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Broker-Api-Key": env("BROKER_API_KEY"),
        ...routeProofHeaders,
      },
      body: JSON.stringify(depositPayload),
    });
  } catch (error) {
    recordTokenDeposit({ routeDigest: tenantRoute.payloadDigest, status: "failed", error });
    return textResponse(res, 502, "Failed to deposit tokens with tenant backend");
  }

  if (!depositResponse.ok) {
    recordTokenDeposit({ routeDigest: tenantRoute.payloadDigest, status: "failed", httpStatus: depositResponse.status });
    console.error("Token deposit failed:", depositResponse.status);
    return textResponse(res, 502, "Failed to deposit tokens with tenant backend");
  }
  recordTokenDeposit({ routeDigest: tenantRoute.payloadDigest, status: "success" });

  const depositResult = await depositResponse.json();
  const authCode = extractDepositAuthCode(depositResult);
  if (!authCode) {
    recordTokenDeposit({ routeDigest: tenantRoute.payloadDigest, status: "failed", error: new SyntaxError("missing auth code") });
    console.error("Token deposit response missing auth_code");
    return textResponse(res, 502, "Token deposit response missing auth_code");
  }

  const redirectTarget = buildPostAuthRedirect({ tenant, authCode, returnTo });
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
// POST /github-app/installation-token
// ---------------------------------------------------------------------------
export async function handleGitHubInstallationToken(req, res) {
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

  const owner = body.owner || "FemLed";
  const repo = body.repo;
  const permissions = sanitizeGitHubPermissions(body.permissions);

  if (!repo || !isSafeRepoComponent(owner) || !isSafeRepoComponent(repo)) {
    return jsonResponse(res, 400, { error: "owner and repo must be safe GitHub identifiers" });
  }

  if (!env("GITHUB_APP_ID") || !env("GITHUB_APP_PRIVATE_KEY")) {
    return jsonResponse(res, 500, { error: "GitHub App secrets are not configured" });
  }

  try {
    const { installationId, tokenData } = await createGitHubRepoInstallationToken({ owner, repo, permissions });

    return jsonResponse(res, 200, {
      token: tokenData.token,
      expiresAt: tokenData.expires_at,
      installationId,
      repository: { owner, repo },
      permissions: tokenData.permissions || permissions,
    });
  } catch (error) {
    console.error("GitHub installation token issue failed:", error);
    return jsonResponse(res, 502, {
      error: "Failed to issue GitHub installation token",
      details: error.message,
    });
  }
}

export async function createGitHubRepoInstallationToken({ owner = "FemLed", repo, permissions = null } = {}) {
  if (!repo || !isSafeRepoComponent(owner) || !isSafeRepoComponent(repo)) {
    throw new Error("owner and repo must be safe GitHub identifiers");
  }
  if (!env("GITHUB_APP_ID") || !env("GITHUB_APP_PRIVATE_KEY")) {
    throw new Error("GitHub App secrets are not configured");
  }
  const appJwt = getGitHubAppJwt();
  const installationId = await getGitHubInstallationId(appJwt, owner, repo);
  const tokenData = await createInstallationToken(appJwt, installationId, repo, sanitizeGitHubPermissions(permissions));
  return { installationId, tokenData };
}

// ---------------------------------------------------------------------------
// POST /push/send-silent
// ---------------------------------------------------------------------------
// Accepts device tokens from a couple's server and sends silent push
// notifications via APNs after verifying token ownership. New tokens are
// verified via a callback to the couple's own server (resolved from the
// broker's trusted `couples` collection) and rate-limited by a 12-month
// sliding window on new registrations per couple.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_NEW_TOKENS_PER_YEAR = 20;
const REGISTRY_COLLECTION = "push_device_registry";
const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

export async function handlePushSendSilent(req, res) {
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

  const { coupleId, intentId, deviceTokens, bundleId, apnsEnvironment } = body;
  const useProduction = apnsEnvironment === "production";

  if (!coupleId || !UUID_RE.test(coupleId)) {
    return jsonResponse(res, 400, { error: "coupleId must be a valid UUID" });
  }
  if (!intentId || typeof intentId !== "string") {
    return jsonResponse(res, 400, { error: "intentId is required" });
  }
  if (!Array.isArray(deviceTokens) || deviceTokens.length === 0) {
    return jsonResponse(res, 400, { error: "deviceTokens must be a non-empty array" });
  }
  if (!bundleId || typeof bundleId !== "string") {
    return jsonResponse(res, 400, { error: "bundleId is required" });
  }
  if (deviceTokens.length > 100) {
    return jsonResponse(res, 400, { error: "Maximum 100 device tokens per request" });
  }

  try {
    const knownTokens = [];
    const newTokens = [];

    const lookups = await Promise.all(
      deviceTokens.map((token) => getRegistryDoc(coupleId, token))
    );
    for (let i = 0; i < deviceTokens.length; i++) {
      if (lookups[i]) {
        knownTokens.push(deviceTokens[i]);
      } else {
        newTokens.push(deviceTokens[i]);
      }
    }

    let verifiedNewTokens = [];

    if (newTokens.length > 0) {
      const recentCount = await countRecentRegistrations(coupleId);
      const remaining = MAX_NEW_TOKENS_PER_YEAR - recentCount;

      if (remaining <= 0) {
        console.warn(`[Push] Rate limit exceeded for couple ${coupleId}: ${recentCount} tokens in last 12 months`);
        if (knownTokens.length === 0) {
          return jsonResponse(res, 429, {
            error: "New device token registration rate limit exceeded (20 per 12 months)",
          });
        }
      } else {
        const tokensToVerify = newTokens.slice(0, remaining);

        const tenantRoute = getTenantApiRouteForTenant(coupleId);
        if (!tenantRoute) {
          return jsonResponse(res, 404, { error: "Couple not found" });
        }

        const apiUrl = tenantRoute.payload.apiHost;
        const verifyUrl = `https://${apiUrl}/api/push/verify-tokens?intentId=${encodeURIComponent(intentId)}&tokens=${encodeURIComponent(tokensToVerify.join(","))}`;
        const verifyResponse = await fetch(verifyUrl, {
          headers: {
            "X-Broker-Api-Key": env("BROKER_API_KEY"),
            ...buildPrivacySafeRouteProofHeaders(tenantRoute),
          },
        });

        if (verifyResponse.ok) {
          const verifyResult = await verifyResponse.json();
          verifiedNewTokens = (verifyResult.verified || []).filter((t) =>
            tokensToVerify.includes(t)
          );

          await Promise.all(
            verifiedNewTokens.map((token) => upsertRegistryDoc(coupleId, token))
          );

          if (verifiedNewTokens.length > 0) {
            console.log(`[Push] Registered ${verifiedNewTokens.length} new token(s) for couple ${coupleId}`);
          }
        } else {
          console.warn(`[Push] Verification callback failed (${verifyResponse.status}) for couple ${coupleId}`);
        }
      }
    }

    const tokensToSend = [...knownTokens, ...verifiedNewTokens];
    if (tokensToSend.length === 0) {
      return jsonResponse(res, 200, { sent: 0, failed: 0, gone: [] });
    }

    await Promise.all(
      knownTokens.map((token) => touchRegistryLastSeen(coupleId, token))
    );

    const result = await sendSilentPush(tokensToSend, bundleId, useProduction);
    console.log(`[Push] Silent push for ${coupleId}: ${result.sent} sent, ${result.failed} failed, ${result.gone.length} expired`);
    return jsonResponse(res, 200, result);
  } catch (error) {
    console.error("[Push] Error sending silent push:", error.message);
    return jsonResponse(res, 500, { error: "Failed to send push notification" });
  }
}

// ---------------------------------------------------------------------------
// POST /push/send-alert
// ---------------------------------------------------------------------------
// Accepts device tokens from a couple's server and sends a user-visible
// APNs alert push after verifying token ownership. Shares the same
// intent-verification + per-couple token registry as /push/send-silent.
//
// This endpoint is reserved for Time Sensitive delivery (e.g. haptic
// compliance pushes for the FemLedCoach widget app). The broker rejects
// any attempt to send `interruption-level: critical` to ensure Critical
// Alerts are never issued via this path, regardless of caller intent.

const ALLOWED_INTERRUPTION_LEVELS = new Set(["time-sensitive", "active", "passive"]);

export async function handlePushSendAlert(req, res) {
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

  const {
    coupleId,
    intentId,
    deviceTokens,
    bundleId,
    apnsEnvironment,
    alert,
    sound,
    badge,
    interruptionLevel,
    threadId,
    customData,
  } = body;
  const useProduction = apnsEnvironment === "production";

  if (!coupleId || !UUID_RE.test(coupleId)) {
    return jsonResponse(res, 400, { error: "coupleId must be a valid UUID" });
  }
  if (!intentId || typeof intentId !== "string") {
    return jsonResponse(res, 400, { error: "intentId is required" });
  }
  if (!Array.isArray(deviceTokens) || deviceTokens.length === 0) {
    return jsonResponse(res, 400, { error: "deviceTokens must be a non-empty array" });
  }
  if (!bundleId || typeof bundleId !== "string") {
    return jsonResponse(res, 400, { error: "bundleId is required" });
  }
  if (deviceTokens.length > 100) {
    return jsonResponse(res, 400, { error: "Maximum 100 device tokens per request" });
  }
  if (alert === undefined || alert === null) {
    return jsonResponse(res, 400, { error: "alert is required" });
  }
  if (interruptionLevel === "critical") {
    return jsonResponse(res, 400, { error: "Critical interruption level is not allowed" });
  }
  if (interruptionLevel && !ALLOWED_INTERRUPTION_LEVELS.has(interruptionLevel)) {
    return jsonResponse(res, 400, { error: "interruptionLevel must be one of time-sensitive, active, passive" });
  }
  if (sound && typeof sound === "object" && sound.critical) {
    return jsonResponse(res, 400, { error: "Critical sound is not allowed" });
  }
  if (customData && typeof customData !== "object") {
    return jsonResponse(res, 400, { error: "customData must be an object" });
  }
  if (customData && Object.prototype.hasOwnProperty.call(customData, "aps")) {
    return jsonResponse(res, 400, { error: "customData.aps is not allowed" });
  }

  try {
    const tokensToSend = await resolvePushTokens({
      coupleId,
      intentId,
      deviceTokens,
    });

    if (tokensToSend === null) {
      return jsonResponse(res, 429, {
        error: "New device token registration rate limit exceeded (20 per 12 months)",
      });
    }

    if (tokensToSend.length === 0) {
      return jsonResponse(res, 200, { sent: 0, failed: 0, gone: [] });
    }

    const result = await sendAlertPush(tokensToSend, bundleId, {
      alert,
      sound,
      badge,
      interruptionLevel: interruptionLevel || "time-sensitive",
      threadId,
      customData,
    }, useProduction);

    console.log(`[Push] Alert push for ${coupleId}: ${result.sent} sent, ${result.failed} failed, ${result.gone.length} expired`);
    return jsonResponse(res, 200, result);
  } catch (error) {
    console.error("[Push] Error sending alert push:", error.message);
    return jsonResponse(res, 500, { error: "Failed to send push notification" });
  }
}

/**
 * Shared between /push/send-silent and /push/send-alert: resolves the subset
 * of `deviceTokens` that this broker may legitimately push to on behalf of
 * `coupleId`. Known tokens pass through; new tokens are verified via the
 * couple's `api-*` callback and subject to a 20/year registration cap.
 *
 * Returns `null` when the rate limit is exceeded and no known tokens exist
 * (so callers can respond with 429), an empty array when nothing is sendable,
 * or the concrete list of hex device tokens to push.
 */
async function resolvePushTokens({ coupleId, intentId, deviceTokens }) {
  const knownTokens = [];
  const newTokens = [];

  const lookups = await Promise.all(
    deviceTokens.map((token) => getRegistryDoc(coupleId, token))
  );
  for (let i = 0; i < deviceTokens.length; i++) {
    if (lookups[i]) {
      knownTokens.push(deviceTokens[i]);
    } else {
      newTokens.push(deviceTokens[i]);
    }
  }

  let verifiedNewTokens = [];

  if (newTokens.length > 0) {
    const recentCount = await countRecentRegistrations(coupleId);
    const remaining = MAX_NEW_TOKENS_PER_YEAR - recentCount;

    if (remaining <= 0) {
      console.warn(`[Push] Rate limit exceeded for couple ${coupleId}: ${recentCount} tokens in last 12 months`);
      if (knownTokens.length === 0) {
        return null;
      }
    } else {
      const tokensToVerify = newTokens.slice(0, remaining);

      const tenantRoute = getTenantApiRouteForTenant(coupleId);
      if (!tenantRoute) {
        throw new Error("Couple not found");
      }

      const apiUrl = tenantRoute.payload.apiHost;
      const verifyUrl = `https://${apiUrl}/api/push/verify-tokens?intentId=${encodeURIComponent(intentId)}&tokens=${encodeURIComponent(tokensToVerify.join(","))}`;
      const verifyResponse = await fetch(verifyUrl, {
        headers: {
          "X-Broker-Api-Key": env("BROKER_API_KEY"),
          ...buildPrivacySafeRouteProofHeaders(tenantRoute),
        },
      });

      if (verifyResponse.ok) {
        const verifyResult = await verifyResponse.json();
        verifiedNewTokens = (verifyResult.verified || []).filter((t) =>
          tokensToVerify.includes(t)
        );

        await Promise.all(
          verifiedNewTokens.map((token) => upsertRegistryDoc(coupleId, token))
        );

        if (verifiedNewTokens.length > 0) {
          console.log(`[Push] Registered ${verifiedNewTokens.length} new token(s) for couple ${coupleId}`);
        }
      } else {
        console.warn(`[Push] Verification callback failed (${verifyResponse.status}) for couple ${coupleId}`);
      }
    }
  }

  const tokensToSend = [...knownTokens, ...verifiedNewTokens];

  await Promise.all(
    knownTokens.map((token) => touchRegistryLastSeen(coupleId, token))
  );

  return tokensToSend;
}

// ---------------------------------------------------------------------------
// Push device registry helpers (Firestore REST API)
// ---------------------------------------------------------------------------

async function getRegistryDoc(coupleId, deviceToken) {
  const accessToken = await getMetadataAccessToken();
  if (!accessToken) return null;

  const docId = `${coupleId}_${deviceToken}`;
  const projectId = getProjectId();
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${REGISTRY_COLLECTION}/${docId}`;

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  return response.ok ? await response.json() : null;
}

async function countRecentRegistrations(coupleId) {
  const accessToken = await getMetadataAccessToken();
  if (!accessToken) return MAX_NEW_TOKENS_PER_YEAR;

  const projectId = getProjectId();
  const cutoff = new Date(Date.now() - YEAR_MS).toISOString();
  const queryUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`;

  const response = await fetch(queryUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: REGISTRY_COLLECTION }],
        where: {
          compositeFilter: {
            op: "AND",
            filters: [
              {
                fieldFilter: {
                  field: { fieldPath: "coupleId" },
                  op: "EQUAL",
                  value: { stringValue: coupleId },
                },
              },
              {
                fieldFilter: {
                  field: { fieldPath: "firstSeen" },
                  op: "GREATER_THAN_OR_EQUAL",
                  value: { timestampValue: cutoff },
                },
              },
            ],
          },
        },
        select: { fields: [{ fieldPath: "__name__" }] },
      },
    }),
  });

  if (!response.ok) {
    const errText = await response.text().catch(() => "");
    if (response.status === 400 && errText.includes("index")) {
      console.warn(`[Push] Registry velocity query needs composite index — allowing (verification callback is the primary control)`);
      return 0;
    }
    console.error(`[Push] Registry velocity query failed (${response.status}): ${errText}`);
    return 0;
  }

  const results = await response.json();
  return Array.isArray(results)
    ? results.filter((r) => r.document).length
    : 0;
}

async function upsertRegistryDoc(coupleId, deviceToken) {
  const accessToken = await getMetadataAccessToken();
  if (!accessToken) return;

  const docId = `${coupleId}_${deviceToken}`;
  const projectId = getProjectId();
  const now = new Date().toISOString();
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${REGISTRY_COLLECTION}/${docId}`;

  await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      fields: {
        coupleId: { stringValue: coupleId },
        deviceToken: { stringValue: deviceToken },
        firstSeen: { timestampValue: now },
        lastSeen: { timestampValue: now },
      },
    }),
  });
}

async function touchRegistryLastSeen(coupleId, deviceToken) {
  const accessToken = await getMetadataAccessToken();
  if (!accessToken) return;

  const docId = `${coupleId}_${deviceToken}`;
  const projectId = getProjectId();
  const now = new Date().toISOString();
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${REGISTRY_COLLECTION}/${docId}?updateMask.fieldPaths=lastSeen`;

  await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      fields: {
        lastSeen: { timestampValue: now },
      },
    }),
  });
}

// ---------------------------------------------------------------------------
// Signed tenant route lookup
// ---------------------------------------------------------------------------
function getTenantApiRouteForTenant(uuid) {
  const route = getTenantApiRoute(uuid);
  if (!route) {
    recordTenantRouteLookup({ status: "failed", lookupDigest: sha256Digest(uuid) });
    console.error(`Tenant ${uuid} has no verified signed API route`);
    return null;
  }
  return route;
}

function buildPrivacySafeRouteProofHeaders(route) {
  try {
    return buildRouteProofHeaders(route);
  } catch (error) {
    recordRouteProof({
      routeDigest: route?.payloadDigest || null,
      status: "failed",
      error: Object.assign(error, { code: "ROUTE_PROOF_FAILED" }),
    });
    throw error;
  }
}

// ---------------------------------------------------------------------------
// HMAC state signing/verification
// ---------------------------------------------------------------------------
function signState(payload, secret) {
  const data = base64UrlEncode(payload);
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(data);
  const sig = hmac.digest("hex");
  return `${data}.${sig}`;
}

function verifyState(state, secret) {
  const dotIndex = state.lastIndexOf(".");
  if (dotIndex === -1) return null;

  const data = state.substring(0, dotIndex);
  const sig = state.substring(dotIndex + 1);

  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(data);
  const expected = hmac.digest("hex");

  if (sig.length !== expected.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return null;
  }

  try {
    const parsed = JSON.parse(base64UrlDecode(data));
    if (!parsed?.tenant || typeof parsed.tenant !== "string") {
      return null;
    }

    const normalizedReturnTo = normalizeReturnTo(parsed.returnTo || null);
    if (parsed.returnTo && !normalizedReturnTo) {
      return null;
    }

    return { tenant: parsed.tenant, returnTo: normalizedReturnTo };
  } catch {
    return { tenant: data, returnTo: null };
  }
}

function normalizeReturnTo(value) {
  if (!value || typeof value !== "string") {
    return null;
  }

  try {
    const parsed = new URL(value);
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      return null;
    }

    const normalized = `${parsed.protocol}//${parsed.host}${parsed.pathname}`.replace(/\/$/, "");
    return ALLOWED_NATIVE_RETURN_TO.has(normalized) ? normalized : null;
  } catch {
    return null;
  }
}

export function buildPostAuthRedirect({ tenant, authCode, returnTo }) {
  if (returnTo) {
    const callbackUrl = new URL(returnTo);
    callbackUrl.searchParams.set("auth_success", "true");
    callbackUrl.searchParams.set("tenant", tenant);
    callbackUrl.searchParams.set("auth_code", authCode);
    return callbackUrl.toString();
  }

  return `https://app-${tenant}.femled.ai${DEFAULT_POST_LOGIN_PATH}?auth_success=true&auth_code=${encodeURIComponent(authCode)}`;
}

export function extractDepositAuthCode(depositResult) {
  return typeof depositResult?.auth_code === "string" && depositResult.auth_code
    ? depositResult.auth_code
    : null;
}

function isSafeRepoComponent(value) {
  return typeof value === "string" && /^[A-Za-z0-9._-]+$/.test(value);
}

function sanitizeGitHubPermissions(inputPermissions) {
  const defaultPermissions = {
    contents: "write",
    pull_requests: "write",
  };

  if (!inputPermissions || typeof inputPermissions !== "object") {
    return defaultPermissions;
  }

  const allowedPermissions = new Set([
    "contents",
    "pull_requests",
    "issues",
    "checks",
    "statuses",
    "workflows",
  ]);
  const allowedLevels = new Set(["read", "write"]);
  const sanitized = {};

  for (const [key, value] of Object.entries(inputPermissions)) {
    if (!allowedPermissions.has(key) || !allowedLevels.has(value)) {
      continue;
    }
    sanitized[key] = value;
  }

  if (!sanitized.contents) sanitized.contents = "write";
  if (!sanitized.pull_requests) sanitized.pull_requests = "write";

  return sanitized;
}

function getGitHubAppJwt() {
  const nowMs = Date.now();
  if (githubAppJwtCache && githubAppJwtCache.expiresAt > nowMs) {
    return githubAppJwtCache.token;
  }

  const appId = env("GITHUB_APP_ID");
  const privateKey = normalizePem(env("GITHUB_APP_PRIVATE_KEY"));
  const nowSeconds = Math.floor(nowMs / 1000);

  const header = base64UrlEncode({ alg: "RS256", typ: "JWT" });
  const payload = base64UrlEncode({
    iat: nowSeconds - 60,
    exp: nowSeconds + 9 * 60,
    iss: appId,
  });

  const unsignedToken = `${header}.${payload}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsignedToken);
  signer.end();
  const signature = signer.sign(privateKey).toString("base64url");
  const token = `${unsignedToken}.${signature}`;

  githubAppJwtCache = {
    token,
    expiresAt: nowMs + 8 * 60 * 1000,
  };

  return token;
}

function normalizePem(value) {
  return value.includes("\\n") ? value.replace(/\\n/g, "\n") : value;
}

function base64UrlEncode(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function base64UrlDecode(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

async function getGitHubInstallationId(appJwt, owner, repo) {
  const response = await fetch(`${GITHUB_API_BASE}/repos/${owner}/${repo}/installation`, {
    method: "GET",
    headers: githubHeaders(appJwt),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GitHub installation lookup failed (${response.status}): ${errorText}`);
  }

  const data = await response.json();
  if (!data.id) {
    throw new Error("GitHub installation lookup returned no installation id");
  }

  return data.id;
}

async function createInstallationToken(appJwt, installationId, repo, permissions) {
  const response = await fetch(`${GITHUB_API_BASE}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: githubHeaders(appJwt),
    body: JSON.stringify({
      repositories: [repo],
      permissions,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GitHub installation token creation failed (${response.status}): ${errorText}`);
  }

  return response.json();
}

function githubHeaders(bearerToken) {
  return {
    Authorization: `Bearer ${bearerToken}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json",
    "User-Agent": "FemLed-Auth-Broker",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

// ---------------------------------------------------------------------------
// POST /github-app/repo-webhook
// ---------------------------------------------------------------------------
// Receives GitHub org-level push webhooks and fans them out to the correct
// couple's Cloud Build webhook trigger. The broker verifies the webhook
// signature and resolves repo_name -> trigger URL only through verified,
// tenant-signed deployment webhook route records.

export async function handleGitHubRepoWebhook(req, res) {
  if (req.method !== "POST") {
    return textResponse(res, 405, "Method not allowed");
  }

  const body = await readRawBody(req);
  if (!body) {
    return jsonResponse(res, 400, { error: "Empty request body" });
  }

  const signature = req.headers["x-hub-signature-256"];
  if (!signature) {
    return jsonResponse(res, 401, { error: "Missing X-Hub-Signature-256 header" });
  }

  const webhookSecret = env("GITHUB_WEBHOOK_SECRET");
  if (!webhookSecret) {
    console.error("[RepoWebhook] GITHUB_WEBHOOK_SECRET not configured");
    return jsonResponse(res, 500, { error: "Webhook secret not configured" });
  }

  const expected = "sha256=" + crypto.createHmac("sha256", webhookSecret).update(body).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    console.error("[RepoWebhook] Invalid webhook signature");
    return jsonResponse(res, 401, { error: "Invalid signature" });
  }

  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    return jsonResponse(res, 400, { error: "Invalid JSON body" });
  }

  const ref = payload.ref || "";
  if (ref !== "refs/heads/master") {
    return jsonResponse(res, 200, { ignored: true, reason: `ref ${ref} is not master` });
  }

  const repoName = payload.repository?.name;
  if (!repoName) {
    return jsonResponse(res, 400, { error: "Missing repository.name in payload" });
  }

  console.log(`[RepoWebhook] Push to master on ${repoName}, resolving couple...`);

  const deployRoute = getDeployWebhookRouteForRepo(repoName);
  if (!deployRoute) {
    recordDeployWebhook({
      repoDigest: sha256Digest(repoName),
      status: "failed",
      error: Object.assign(new Error("missing route"), { code: "MISSING_ROUTE" }),
    });
    console.error(`[RepoWebhook] No deploy trigger URL found for repo: ${repoName}`);
    return jsonResponse(res, 404, { error: "No couple found for this repository" });
  }
  const triggerUrl = deployRoute.payload.cloudBuildDeployTriggerUrl;

  try {
    const forwardResponse = await fetch(triggerUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    const status = forwardResponse.status;
    if (!forwardResponse.ok) {
      recordDeployWebhook({ routeDigest: deployRoute.payloadDigest, status: "failed", httpStatus: status });
    } else {
      recordDeployWebhook({ routeDigest: deployRoute.payloadDigest, status: "success", httpStatus: status });
    }
    console.log(`[RepoWebhook] Forwarded to Cloud Build trigger for ${repoName}: ${status}`);
    return jsonResponse(res, 200, { forwarded: true, repo: repoName, triggerStatus: status });
  } catch (error) {
    recordDeployWebhook({ routeDigest: deployRoute.payloadDigest, status: "failed", error });
    console.error(`[RepoWebhook] Failed to forward to Cloud Build trigger:`, error.message);
    return jsonResponse(res, 502, { error: "Failed to forward to Cloud Build trigger" });
  }
}

/**
 * Read the raw request body as a string (needed for HMAC signature verification
 * where the signature must be computed over the exact bytes received).
 */
function readRawBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data || null));
    req.on("error", () => resolve(null));
  });
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

import crypto from "node:crypto";
import http2 from "node:http2";

const APNS_HOST_PROD = "api.push.apple.com";
const APNS_HOST_DEV = "api.sandbox.push.apple.com";
const APNS_PORT = 443;
const JWT_TTL_MS = 50 * 60 * 1000; // 50 minutes (Apple allows up to 60)

let signingKey = null;
let keyId = null;
let teamId = null;
let jwtCache = null;

export function initApns({ authKeyPem, authKeyId, appleTeamId }) {
  signingKey = crypto.createPrivateKey(authKeyPem);
  keyId = authKeyId;
  teamId = appleTeamId;
  console.log("[APNs] Initialized with keyId:", keyId);
}

function getApnsJwt() {
  const now = Date.now();
  if (jwtCache && jwtCache.expiresAt > now) {
    return jwtCache.token;
  }

  const issuedAt = Math.floor(now / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "ES256", kid: keyId })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ iss: teamId, iat: issuedAt })).toString("base64url");

  const signer = crypto.createSign("SHA256");
  signer.update(`${header}.${payload}`);
  signer.end();
  const signature = signer.sign(signingKey).toString("base64url");

  const token = `${header}.${payload}.${signature}`;
  jwtCache = { token, expiresAt: now + JWT_TTL_MS };
  return token;
}

/**
 * Send a silent push notification to the given device tokens.
 * @param {string[]} deviceTokens - Hex-encoded APNs device tokens
 * @param {string} bundleId - App bundle ID (e.g. "ai.femled.coach")
 * @param {boolean} [production=true] - Use production APNs endpoint
 * @returns {Promise<{sent: number, failed: number, gone: string[]}>}
 */
export async function sendSilentPush(deviceTokens, bundleId, production = true) {
  if (!signingKey) {
    throw new Error("[APNs] Not initialized -- call initApns() first");
  }

  if (!deviceTokens || deviceTokens.length === 0) {
    return { sent: 0, failed: 0, gone: [] };
  }

  const jwt = getApnsJwt();
  const host = production ? APNS_HOST_PROD : APNS_HOST_DEV;

  const results = await Promise.allSettled(
    deviceTokens.map((token) => sendOneNotification(host, jwt, bundleId, token))
  );

  return collectResults(deviceTokens, results);
}

/**
 * Send a user-visible alert push to the given device tokens.
 *
 * Intended for Time Sensitive haptic compliance notifications to the coach
 * widget app. Critical alerts are not supported here: the broker rejects any
 * attempt to send `interruption-level: critical` (or `sound.critical: 1`) so
 * this path can never escalate beyond Time Sensitive, even if a couple's
 * server is compromised.
 *
 * @param {string[]} deviceTokens
 * @param {string} bundleId
 * @param {Object} payload
 * @param {Object|string} payload.alert - APNs alert (dict with title/body or string)
 * @param {string|Object} [payload.sound="default"]
 * @param {number} [payload.badge]
 * @param {"time-sensitive"|"active"|"passive"} [payload.interruptionLevel]
 * @param {string} [payload.threadId]
 * @param {Object} [payload.customData] - Top-level keys merged alongside `aps`
 * @param {boolean} [production=true]
 * @returns {Promise<{sent: number, failed: number, gone: string[], details: Array}>}
 */
export async function sendAlertPush(deviceTokens, bundleId, payload, production = true) {
  if (!signingKey) {
    throw new Error("[APNs] Not initialized -- call initApns() first");
  }

  if (!deviceTokens || deviceTokens.length === 0) {
    return { sent: 0, failed: 0, gone: [], details: [] };
  }

  const bodyStr = buildAlertPushBody(payload);

  const jwt = getApnsJwt();
  const host = production ? APNS_HOST_PROD : APNS_HOST_DEV;

  const results = await Promise.allSettled(
    deviceTokens.map((token) => sendOneNotification(host, jwt, bundleId, token, {
      body: bodyStr,
      pushType: "alert",
      priority: "10",
    }))
  );

  return collectResults(deviceTokens, results);
}

export function buildAlertPushBody(payload) {
  if (!payload || typeof payload !== "object") {
    throw new Error("[APNs] sendAlertPush requires a payload object");
  }

  if (payload.interruptionLevel === "critical") {
    throw new Error("[APNs] Critical interruption level is not allowed via sendAlertPush");
  }

  if (payload.sound && typeof payload.sound === "object" && payload.sound.critical) {
    throw new Error("[APNs] Critical sound is not allowed via sendAlertPush");
  }

  const customData = payload.customData || {};
  if (Object.prototype.hasOwnProperty.call(customData, "aps")) {
    throw new Error("[APNs] customData.aps is not allowed");
  }

  const aps = {};
  if (payload.alert !== undefined) aps.alert = payload.alert;
  aps.sound = payload.sound || "default";
  if (payload.badge !== undefined) aps.badge = payload.badge;
  if (payload.interruptionLevel) aps["interruption-level"] = payload.interruptionLevel;
  if (payload.threadId) aps["thread-id"] = payload.threadId;

  return JSON.stringify({ ...customData, aps });
}

function collectResults(deviceTokens, results) {
  let sent = 0;
  let failed = 0;
  const gone = [];
  const details = [];

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const tokenSuffix = deviceTokens[i].slice(-8);
    if (result.status === "fulfilled") {
      if (result.value.success) {
        sent++;
        details.push({ token: tokenSuffix, status: 200 });
      } else {
        failed++;
        details.push({ token: tokenSuffix, status: result.value.status, reason: result.value.reason || "unknown" });
        if (result.value.status === 410) {
          gone.push(deviceTokens[i]);
        }
      }
    } else {
      failed++;
      details.push({ token: tokenSuffix, status: 0, reason: result.reason?.message || "promise_rejected" });
    }
  }

  return { sent, failed, gone, details };
}

function sendOneNotification(host, jwt, bundleId, deviceToken, options = {}) {
  const body = options.body ?? JSON.stringify({ aps: { "content-available": 1 } });
  const pushType = options.pushType ?? "background";
  const priority = options.priority ?? "5";

  return new Promise((resolve) => {
    const client = http2.connect(`https://${host}:${APNS_PORT}`);

    client.on("error", (err) => {
      console.error("[APNs] Connection error:", err.message);
      resolve({ success: false, status: 0 });
    });

    const headers = {
      ":method": "POST",
      ":path": `/3/device/${deviceToken}`,
      "authorization": `bearer ${jwt}`,
      "apns-topic": bundleId,
      "apns-push-type": pushType,
      "apns-priority": priority,
      "apns-expiration": String(Math.floor(Date.now() / 1000) + 3600),
      "content-type": "application/json",
    };

    const req = client.request(headers);

    let responseData = "";
    let statusCode = 0;

    req.on("response", (hdrs) => {
      statusCode = hdrs[":status"];
    });

    req.on("data", (chunk) => {
      responseData += chunk;
    });

    req.on("end", () => {
      client.close();
      if (statusCode === 200) {
        resolve({ success: true, status: 200 });
      } else {
        let reason = `http_${statusCode}`;
        if (responseData) {
          try {
            const parsed = JSON.parse(responseData);
            reason = parsed.reason || reason;
          } catch { /* use default reason */ }
        }
        resolve({ success: false, status: statusCode, reason });
      }
    });

    req.on("error", (err) => {
      client.close();
      console.error("[APNs] Request error:", err.message);
      resolve({ success: false, status: 0 });
    });

    req.end(body);
  });
}

import http from "node:http";
import { jsonResponse } from "./http-helpers.js";

const ATTESTATION_AUDIENCE = "https://oauth-tee.femled.ai";
const LAUNCHER_SOCKET = "/run/container_launcher/teeserver.sock";
const REFRESH_INTERVAL_MS = 10 * 60 * 1000;

let cachedToken = null;

/**
 * GET /attestation
 *
 * Two modes:
 *
 *   1. No nonce (programmatic): returns a pre-cached attestation token
 *      instantly. The token is refreshed in the background every 10 minutes.
 *      Callers verify freshness via the `exp` claim.
 *
 *   2. With nonce (manual verification per VERIFICATION.md): makes a live
 *      call to the Confidential Space launcher to produce a token bound to
 *      the caller's nonce. This is slow (10-15s) but proves freshness via
 *      `eat_nonce`.
 *
 * The custom audience ("https://oauth-tee.femled.ai") ensures neither token
 * variant can be used for STS exchange (which requires
 * "https://sts.googleapis.com").
 */
export async function handleAttestation(url, req, res) {
  const nonces = url.searchParams.getAll("nonce");

  if (nonces.length === 0) {
    if (!cachedToken) {
      try {
        cachedToken = await requestAttestationToken([]);
      } catch (err) {
        console.error("Attestation cache miss, launcher call failed:", err.message);
        return jsonResponse(res, 503, {
          error: "Attestation token not yet available. Try again shortly.",
        });
      }
    }

    res.writeHead(200, {
      "Content-Type": "application/jwt",
      "Cache-Control": "public, max-age=300",
    });
    return res.end(cachedToken);
  }

  for (const n of nonces) {
    if (n.length < 8 || n.length > 88) {
      return jsonResponse(res, 400, {
        error: "Each nonce must be between 8 and 88 bytes.",
      });
    }
  }

  try {
    const token = await requestAttestationToken(nonces);

    res.writeHead(200, {
      "Content-Type": "application/jwt",
      "Cache-Control": "no-store",
    });
    res.end(token);
  } catch (err) {
    console.error("Attestation endpoint error:", err.message);
    return jsonResponse(res, 500, {
      error: "Attestation service unavailable.",
    });
  }
}

/**
 * Starts a background loop that refreshes the cached attestation token
 * every 10 minutes. Called once from server.js after startup.
 */
export function startAttestationRefreshLoop() {
  async function refresh() {
    try {
      cachedToken = await requestAttestationToken([]);
      console.log("[Attestation] Cached token refreshed");
    } catch (err) {
      console.error("[Attestation] Background refresh failed:", err.message);
    }
  }

  refresh();
  setInterval(refresh, REFRESH_INTERVAL_MS);
}

function requestAttestationToken(nonces) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      audience: ATTESTATION_AUDIENCE,
      token_type: "OIDC",
      nonces,
    });

    const options = {
      socketPath: LAUNCHER_SOCKET,
      path: "/v1/token",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const request = http.request(options, (response) => {
      let data = "";
      response.on("data", (chunk) => (data += chunk));
      response.on("end", () => {
        if (response.statusCode === 200) {
          resolve(data);
        } else {
          reject(new Error(`Launcher returned ${response.statusCode}: ${data}`));
        }
      });
    });

    request.on("error", (err) => reject(err));
    request.write(body);
    request.end();
  });
}

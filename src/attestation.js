import http from "node:http";
import { jsonResponse } from "./http-helpers.js";

const ATTESTATION_AUDIENCE = "https://oauth-tee.femled.ai";
const LAUNCHER_SOCKET = "/run/container_launcher/teeserver.sock";

/**
 * GET /attestation?nonce=<value>
 *
 * Returns a fresh Confidential Space attestation token with a custom
 * audience and the caller's nonce. The token is a JWT signed by Google's
 * attestation service -- the caller validates it against Google's public
 * keys, not against anything FemLed controls.
 *
 * The custom audience ("https://oauth-tee.femled.ai") ensures this token
 * cannot be used for STS exchange (which requires "https://sts.googleapis.com").
 */
export async function handleAttestation(url, req, res) {
  const nonces = url.searchParams.getAll("nonce");

  if (nonces.length === 0) {
    return jsonResponse(res, 400, {
      error: "Missing required 'nonce' query parameter. Provide a random value (8-88 bytes) to bind the token to your verification session.",
    });
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

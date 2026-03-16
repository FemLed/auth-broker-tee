import { jsonResponse, textResponse } from "./http-helpers.js";

const ATTESTATION_AUDIENCE = "https://oauth-tee.femled.ai";
const LAUNCHER_TOKEN_URL = "http://localhost/v1/token";

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
 *
 * Verification:
 *   1. Decode the JWT and verify the signature against Google's JWKS at
 *      https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
 *   2. Check aud == "https://oauth-tee.femled.ai"
 *   3. Check eat_nonce contains the nonce you provided
 *   4. Inspect submods.container.image_digest, dbgstat, swname, etc.
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
    const response = await fetch(LAUNCHER_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        audience: ATTESTATION_AUDIENCE,
        token_type: "OIDC",
        nonces,
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error("Attestation token request failed:", response.status);
      return jsonResponse(res, 502, {
        error: "Failed to obtain attestation token from Confidential Space launcher.",
      });
    }

    const token = await response.text();

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

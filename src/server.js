import https from "node:https";
import http from "node:http";
import { fetchSecretByName } from "./gcp-auth.js";
import {
  handleLogin,
  handleCallback,
  handleRefresh,
  handleGitHubInstallationToken,
} from "./routes.js";
import { handleAttestation, startAttestationRefreshLoop } from "./attestation.js";
import { jsonResponse, textResponse } from "./http-helpers.js";
import { loadTlsCredentials } from "./tls.js";
import { startRenewalLoop } from "./acme-renewal.js";

const PORT = 443;
const HEALTH_PORT = 8080;

/**
 * Secret names are hardcoded here so they are auditable in the public source
 * code. The operator cannot influence which secrets the workload reads --
 * access is controlled by WIF attestation policy tied to the image digest.
 */
const SECRETS = {
  GOOGLE_CLIENT_ID: "cloudflare-access-google-oauth-client-id",
  GOOGLE_CLIENT_SECRET: "cloudflare-access-google-oauth-client-secret",
  HMAC_SECRET: "auth-broker-hmac-secret",
  BROKER_API_KEY: "broker-api-key",
  CLOUDFLARE_DNS_TOKEN: "auth-broker-cloudflare-dns-token",
  GITHUB_APP_ID: "femled-code-agent-github-app-id",
  GITHUB_APP_PRIVATE_KEY: "femled-code-agent-github-app-private-key",
};

async function loadSecrets() {
  const entries = Object.entries(SECRETS);
  const values = await Promise.all(
    entries.map(([, secretName]) => fetchSecretByName(secretName))
  );
  for (let i = 0; i < entries.length; i++) {
    process.env[entries[i][0]] = values[i];
  }
}

async function main() {
  await loadSecrets();

  const { key, cert } = await loadTlsCredentials();

  const server = https.createServer({ key, cert }, async (req, res) => {
    const url = new URL(req.url, `https://${req.headers.host}`);

    try {
      switch (url.pathname) {
        case "/login":
          return await handleLogin(url, req, res);
        case "/callback":
          return await handleCallback(url, req, res);
        case "/refresh":
          return await handleRefresh(req, res);
        case "/github-app/installation-token":
          return await handleGitHubInstallationToken(req, res);
        case "/attestation":
          return await handleAttestation(url, req, res);
        case "/health":
          return jsonResponse(res, 200, { status: "ok" });
        default:
          return textResponse(res, 404, "Not found");
      }
    } catch (err) {
      console.error("Unhandled error:", err.stack || err.message);
      return jsonResponse(res, 500, { error: "Internal server error" });
    }
  });

  const healthServer = http.createServer((req, res) => {
    if (req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  server.listen(PORT, () => {
    console.log(`Auth broker listening on port ${PORT} (HTTPS)`);
  });

  healthServer.listen(HEALTH_PORT, () => {
    console.log(`Health check listening on port ${HEALTH_PORT} (HTTP)`);
  });

  startRenewalLoop(server);
  startAttestationRefreshLoop();
}

main().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});

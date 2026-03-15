import https from "node:https";
import http from "node:http";
import { handleLogin, handleCallback, handleRefresh } from "./routes.js";
import { jsonResponse, textResponse } from "./http-helpers.js";
import { loadTlsCredentials } from "./tls.js";

const PORT = 443;
const HEALTH_PORT = 8080;

async function main() {
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
}

main().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});

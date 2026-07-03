import https from "node:https";
import http from "node:http";
import { fetchSecretByName } from "./gcp-auth.js";
import {
  handleLogin,
  handleCallback,
  handleRefresh,
  handleGitHubInstallationToken,
  handleGitHubRepoWebhook,
  handlePushSendSilent,
  handlePushSendAlert,
} from "./routes.js";
import {
  handleFirstPrinciplesAdjudicate,
  handleFirstPrinciplesPolicy,
} from "./first-principles-adjudication.js";
import { initApns } from "./apns.js";
import { handleAttestation, startAttestationRefreshLoop } from "./attestation.js";
import {
  handleActivationApply,
  handleActivationComplete,
  handleActivationFinalize,
  handleActivationOffer,
  handleGovernanceChallenge,
  handleGovernanceManifest,
  handleGovernancePreapproval,
  handleGenesisBootstrap,
  handleRepairArtifact,
  handleRepairCandidate,
  handleTenantAdmission,
} from "./governance-routes.js";
import {
  initializeGovernanceAsync,
  isGovernanceActive,
  mayServePath,
  recordAcceptedRouteVersion,
  retryGovernanceRestoreIfDegraded,
  governanceCapsuleHeartbeatIfDue,
  getCapsuleSerial,
  verifyTenantAdmissionEnvelope,
  getGovernanceState,
} from "./governance-state.js";
import { jsonResponse, textResponse } from "./http-helpers.js";
import { startRenewalLoop, bootstrapTls, getTlsRuntimeStatus } from "./acme-renewal.js";
import { getCurrentTlsMaterial, setTlsServer } from "./tls-material.js";
import {
  initializeRouteRegistry,
  setAcceptedRouteRecorder,
  setTenantAdmissionVerifier,
} from "./route-registry.js";
import { startSelfImprovementLoop } from "./governance-self-improvement.js";

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
  GITHUB_APP_ID: "femled-code-agent-github-app-id",
  GITHUB_APP_PRIVATE_KEY: "femled-code-agent-github-app-private-key",
  GITHUB_WEBHOOK_SECRET: "github-org-webhook-secret",
  AUTH_BROKER_DEPLOY_ROUTE_BUNDLE_JSON: "auth-broker-deploy-route-bundle",
  APNS_COACH_AUTH_KEY_P8: "APNS_COACH_AUTH_KEY_P8",
  APNS_COACH_AUTH_KEY_ID: "APNS_COACH_AUTH_KEY_ID",
  APPLE_TEAM_ID: "APPLE_TEAM_ID",
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
  // Self-bootstrap TLS before the listener binds. TLS is ephemeral: there is
  // no sealed capsule to carry over, so every cold boot mints a fresh cert
  // in-enclave via ACME DNS-01. The key+cert live ONLY in process memory --
  // nothing is sealed to KMS or written to GCS/Secret Manager, so a GCP
  // project/org IAM owner has nothing to decrypt. A non-secret mint ledger
  // guards against a reboot loop exhausting the Let's Encrypt weekly limit.
  await bootstrapTls();
  // initializeGovernanceAsync wires up KMS-backed key material (when
  // GOVERNANCE_KMS_SIGNER_KEY_VERSION is configured) and attempts to
  // restore governance state from the latest GCS-backed capsule so a
  // VM restart (host maintenance) does not surface as governance loss.
  // On any restore-time integrity mismatch we fall back to inactive and
  // require the standard genesis or successor flow to re-activate. (TLS is
  // ephemeral and independent of governance restore: it was already minted
  // fresh by bootstrapTls above.)
  await initializeGovernanceAsync();
  setTenantAdmissionVerifier(verifyTenantAdmissionEnvelope);
  setAcceptedRouteRecorder(recordAcceptedRouteVersion);
  await initializeRouteRegistry({ skipTenantRouteDocuments: !isGovernanceActive() });

  if (process.env.APNS_COACH_AUTH_KEY_P8 && process.env.APNS_COACH_AUTH_KEY_ID && process.env.APPLE_TEAM_ID) {
    initApns({
      authKeyPem: process.env.APNS_COACH_AUTH_KEY_P8,
      authKeyId: process.env.APNS_COACH_AUTH_KEY_ID,
      appleTeamId: process.env.APPLE_TEAM_ID,
    });
  } else {
    console.warn("[Server] APNs secrets not available -- /push/send-silent and /push/send-alert will be unavailable");
  }

  const material = getCurrentTlsMaterial();

  const server = https.createServer({ key: material.keyPem, cert: material.certPem }, async (req, res) => {
    const url = new URL(req.url, `https://${req.headers.host}`);

    try {
      if (!mayServePath(url.pathname)) {
        return jsonResponse(res, 423, {
          error: "TEE governance is not active for this route",
        });
      }

      switch (url.pathname) {
        case "/login":
          return await handleLogin(url, req, res);
        case "/callback":
          return await handleCallback(url, req, res);
        case "/refresh":
          return await handleRefresh(req, res);
        case "/push/send-silent":
          return await handlePushSendSilent(req, res);
        case "/push/send-alert":
          return await handlePushSendAlert(req, res);
        case "/github-app/installation-token":
          return await handleGitHubInstallationToken(req, res);
        case "/github-app/repo-webhook":
          return await handleGitHubRepoWebhook(req, res);
        case "/first-principles/adjudicate":
          return await handleFirstPrinciplesAdjudicate(req, res);
        case "/.well-known/femled-tee-policy.json":
          return await handleFirstPrinciplesPolicy(url, req, res);
        case "/.well-known/femled-tee-governance.json":
          return await handleGovernanceManifest(req, res);
        case "/governance/challenge":
          return await handleGovernanceChallenge(req, res);
        case "/governance/preapprove":
          return await handleGovernancePreapproval(req, res);
        case "/governance/genesis-bootstrap":
          return await handleGenesisBootstrap(req, res);
        case "/governance/activation-offer":
          return await handleActivationOffer(req, res);
        case "/governance/activation-complete":
          return await handleActivationComplete(req, res);
        case "/governance/activation-finalize":
          return await handleActivationFinalize(req, res);
        case "/governance/activation-apply":
          return await handleActivationApply(req, res);
        case "/governance/tenant-admission":
          return await handleTenantAdmission(req, res);
        case "/governance/repair-artifact":
          return await handleRepairArtifact(req, res);
        case "/governance/repair-candidate":
          return await handleRepairCandidate(req, res);
        case "/attestation":
          return await handleAttestation(url, req, res);
        case "/health": {
          // Surface governance status/epoch so an external uptime probe can
          // alert on a broker that booted but failed to (re)activate governance
          // (e.g. fail-closed on a KMS outage), instead of it going unnoticed.
          const gov = getGovernanceState();
          return jsonResponse(res, 200, {
            status: "ok",
            governance: { status: gov.status, epoch: gov.epoch, capsuleSerial: getCapsuleSerial() },
            tls: getTlsRuntimeStatus(),
          });
        }
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

  // Hand the listener to the TLS holder so renewals and lineage-driven
  // re-mints rotate the secure context in place (no VM reset).
  setTlsServer(server);

  server.listen(PORT, () => {
    console.log(`Auth broker listening on port ${PORT} (HTTPS)`);
  });

  healthServer.listen(HEALTH_PORT, () => {
    console.log(`Health check listening on port ${HEALTH_PORT} (HTTP)`);
  });

  startRenewalLoop();
  // Inject two governance maintenance ticks onto the attestation refresh
  // cadence: (1) restore-retry so a boot-time KMS outage that left governance
  // inactive (fail-closed) self-heals without operator action or a re-genesis;
  // (2) the capsule heartbeat so the true head is re-sealed periodically and
  // never ages out of the bucket retention window (anti-rollback).
  startAttestationRefreshLoop({
    onTick: async () => {
      await retryGovernanceRestoreIfDegraded();
      await governanceCapsuleHeartbeatIfDue();
    },
  });
  startSelfImprovementLoop();
}

main().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
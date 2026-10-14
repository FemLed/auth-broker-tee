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
  handleActivationAbort,
  handleActivationDecline,
  handleActivationOffer,
  handleActivationProof,
  handleActivationReadiness,
  handleGovernanceChallenge,
  handleGovernanceManifest,
  handleGovernancePreapproval,
  handleGenesisBootstrap,
  handleRepairArtifact,
  handleRepairCandidate,
  handleReplicaCustodyChallenge,
  handleReplicaCustodyRequest,
  handleReplicaHeartbeat,
  handleReplicaManifest,
  handleReplicaPromote,
  handleReplicaSync,
  handleTenantAdmission,
  setReplicaPromotionHandler,
} from "./governance-routes.js";
import {
  getReplicaRole,
  initializeGovernanceAsync,
  isGovernanceActive,
  mayServePath,
  recordAcceptedRouteVersion,
  setGovernanceStateReplicator,
  setReplicaRole,
  verifyTenantAdmissionEnvelope,
  getGovernanceState,
} from "./governance-state.js";
import { replicaConfig, replicateToCustodian, startReplicaSupervisor } from "./governance-replica-custody.js";
import { jsonResponse, parseRequestUrl, textResponse } from "./http-helpers.js";
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
const PUBLIC_SERVICE_RETRY_MS = 15 * 60 * 1000;

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
  // Governance starts inactive with a fresh in-enclave key; it becomes active
  // only through genesis, successor activation, or replica custody.
  await initializeGovernanceAsync();
  const replica = replicaConfig();
  if (replica.peerUrl) setReplicaRole(replica.bootRole);
  setGovernanceStateReplicator(replicateToCustodian);
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

  const replicaServer = http.createServer(handleReplicaPortRequest);
  replicaServer.listen(HEALTH_PORT, () => {
    console.log(`Health and replica custody listening on port ${HEALTH_PORT} (HTTP)`);
  });

  startAttestationRefreshLoop();
  startSelfImprovementLoop();
  // The role a replica is re-keyed into, not its launch role, decides whether
  // it serves: a promoted custodian that restarts comes back as primary.
  startReplicaSupervisor({
    config: replica,
    onCustodyApplied: async () => {
      await initializeRouteRegistry({ skipTenantRouteDocuments: false });
      if (getReplicaRole() === "primary") startPublicServiceWithRetry();
    },
  });

  // A custodian mints no certificate and opens no public listener until an
  // explicit failover promotes it.
  if (replica.peerUrl && replica.bootRole === "custodian") {
    setReplicaPromotionHandler(startPublicServiceWithRetry);
  } else {
    await startPublicServiceWithRetry();
  }
}

// A failed mint keeps the process, and so the in-memory lineage key, alive and
// retries; the mint ledger refuses attempts beyond the weekly budget.
async function startPublicServiceWithRetry() {
  for (;;) {
    try {
      return await startPublicService();
    } catch (error) {
      console.error(`[Server] public service start failed, retrying in ${PUBLIC_SERVICE_RETRY_MS / 60000} min: ${error.message}`);
      await new Promise((resolve) => setTimeout(resolve, PUBLIC_SERVICE_RETRY_MS));
    }
  }
}

async function handleReplicaPortRequest(req, res) {
  try {
    const url = parseRequestUrl(req);
    if (!url) {
      return jsonResponse(res, 400, { error: "Malformed request URL or Host header" });
    }
    switch (url.pathname) {
      case "/health": {
        const gov = getGovernanceState();
        return jsonResponse(res, 200, {
          status: "ok",
          governance: { status: gov.status, epoch: gov.epoch, replicaRole: gov.replicaRole || null },
        });
      }
      case "/replica/manifest":
        return await handleReplicaManifest(req, res);
      case "/replica/custody-challenge":
        return await handleReplicaCustodyChallenge(req, res);
      case "/replica/custody-request":
        return await handleReplicaCustodyRequest(req, res);
      case "/replica/sync":
        return await handleReplicaSync(req, res);
      case "/replica/heartbeat":
        return await handleReplicaHeartbeat(req, res);
      case "/governance/replica-promote":
        return await handleReplicaPromote(req, res);
      default:
        return textResponse(res, 404, "Not found");
    }
  } catch (err) {
    console.error("Unhandled replica-port error:", err.stack || err.message);
    return jsonResponse(res, 500, { error: "Internal server error" });
  }
}

let publicServiceStarted = false;

async function startPublicService() {
  if (publicServiceStarted) return;
  publicServiceStarted = true;
  // TLS is ephemeral: every public-service start mints a fresh cert in-enclave
  // via ACME DNS-01. The key+cert live ONLY in process memory -- nothing is
  // sealed to KMS or written to GCS/Secret Manager, so a GCP project/org IAM
  // owner has nothing to decrypt. A non-secret mint ledger guards against a
  // reboot loop exhausting the Let's Encrypt weekly limit.
  try {
    await bootstrapTls();
  } catch (error) {
    publicServiceStarted = false;
    throw error;
  }
  const material = getCurrentTlsMaterial();

  const server = https.createServer({ key: material.keyPem, cert: material.certPem }, async (req, res) => {
    try {
      const url = parseRequestUrl(req);
      if (!url) {
        return jsonResponse(res, 400, { error: "Malformed request URL or Host header" });
      }

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
        case "/governance/activation-readiness":
          return await handleActivationReadiness(req, res);
        case "/governance/activation-decline":
          return await handleActivationDecline(req, res);
        case "/governance/activation-proof":
          return await handleActivationProof(req, res);
        case "/governance/activation-abort":
          return await handleActivationAbort(req, res);
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
          // alert on a broker that booted but never became active.
          const gov = getGovernanceState();
          return jsonResponse(res, 200, {
            status: "ok",
            governance: { status: gov.status, epoch: gov.epoch },
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

  // Hand the listener to the TLS holder so renewals and lineage-driven
  // re-mints rotate the secure context in place (no VM reset).
  setTlsServer(server);

  server.listen(PORT, () => {
    console.log(`Auth broker listening on port ${PORT} (HTTPS)`);
  });

  startRenewalLoop();
}

main().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
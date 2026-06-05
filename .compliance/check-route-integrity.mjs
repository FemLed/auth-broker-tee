#!/usr/bin/env node
/**
 * Ensures tenant routing cannot regress to mutable Firestore documents.
 *
 * Route records may be transported through untrusted storage, but routing
 * decisions must flow through src/route-registry.js signature verification
 * and tenant-facing calls must carry route proof headers.
 */
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HERE_DEFAULT = path.dirname(fileURLToPath(import.meta.url));
const REPO = process.env.COMPLIANCE_REPO_OVERRIDE
  ? path.resolve(process.env.COMPLIANCE_REPO_OVERRIDE)
  : path.resolve(HERE_DEFAULT, "..");

function emit(status, fields = {}) {
  process.stdout.write(JSON.stringify({ status, ...fields }, null, 2) + "\n");
  process.exit(status === "passed" ? 0 : 1);
}

const routesPath = path.join(REPO, "src", "routes.js");
const registryPath = path.join(REPO, "src", "route-registry.js");
const publicBundlesDir = path.join(REPO, "route-bundles");
const routes = await readFile(routesPath, "utf8");
const registry = await readFile(registryPath, "utf8");

const failures = [];
for (const forbidden of ["api_url", "github_repo_name", "cloudbuild_deploy_trigger_url", "FIRESTORE_COLLECTION = \"couples\""]) {
  if (routes.includes(forbidden)) {
    failures.push(`src/routes.js must not contain mutable Firestore route field ${forbidden}`);
  }
}

for (const required of ["getTenantApiRoute", "getDeployWebhookRouteForRepo", "buildRouteProofHeaders"]) {
  if (!routes.includes(required)) {
    failures.push(`src/routes.js must use signed route registry helper ${required}`);
  }
}

for (const required of [
  "femled.auth_broker.tenant_api_route.v1",
  "femled.auth_broker.deploy_webhook_route.v1",
  "femled.auth_broker.route_document.v1",
  "verifySignedRouteEnvelope",
  "verifyTenantRouteDocument",
  "admissionEnvelope",
  "routeEnvelope",
  "AUTH_BROKER_ROUTE_FIRESTORE_COLLECTION",
  "route signature verification failed",
]) {
  if (!registry.includes(required)) {
    failures.push(`src/route-registry.js missing signed-route invariant: ${required}`);
  }
}

for (const proofHeader of [
  "X-Broker-Route-Digest",
  "X-Broker-Route-Version",
  "X-Broker-Route-Key-Id",
  "X-Broker-Route-Signature",
  "X-Broker-Route-Payload",
]) {
  if (!registry.includes(proofHeader)) {
    failures.push(`route proof header ${proofHeader} is not emitted by route-registry.js`);
  }
}

try {
  for (const entry of await readdir(publicBundlesDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const rel = `route-bundles/${entry.name}`;
    const text = await readFile(path.join(publicBundlesDir, entry.name), "utf8");
    if (text.includes("femled.auth_broker.deploy_webhook_route.v1") || text.includes("cloudBuildDeployTriggerUrl") || text.includes("cloudbuild.googleapis.com")) {
      failures.push(`${rel} is public and must not contain deployment webhook routes or Cloud Build trigger URLs`);
    }
    if (/"tenant"\s*:\s*"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"/i.test(text)) {
      failures.push(`${rel} is public and must not contain live tenant route inventory`);
    }
  }
} catch {
  // No public bundles yet is acceptable.
}

if (failures.length > 0) {
  emit("failed", {
    error: "signed route integrity check failed",
    failures,
  });
}

emit("passed", {
  checked_files: ["src/routes.js", "src/route-registry.js"],
});

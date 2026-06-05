import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { canonicalStringify, sha256Digest, signCanonicalPayload } from "../src/canonical-json.js";
import { createInMemoryGovernanceKeyMaterial, verifyGovernanceEnvelope } from "../src/governance-crypto.js";
import { signTenantAdmissionCertificate } from "../src/governance-certificates.js";
import {
  buildRegistryState,
  buildRouteProofHeaders,
  DEPLOY_WEBHOOK_ROUTE_SCHEMA,
  ROUTE_DOCUMENT_SCHEMA,
  ROUTE_BUNDLE_SCHEMA,
  ROUTE_TRUST_ANCHORS_SCHEMA,
  TENANT_API_ROUTE_SCHEMA,
  verifySignedRouteEnvelope,
} from "../src/route-registry.js";

const TENANT = "019a8314-3e69-7bb1-b8ee-19bc54723979";
const NOW = new Date("2026-05-05T12:00:00Z");

test("signed tenant API route verifies and emits proof headers", () => {
  const keys = generateEd25519PemPair();
  const envelope = signRoute(tenantApiPayload(), keys.privatePem);
  const state = buildRegistryState({
    trustAnchors: trustAnchors(keys.publicPem),
    bundle: { schema: ROUTE_BUNDLE_SCHEMA, routes: [envelope] },
    now: NOW,
  });

  const route = state.tenantApiRoutes.get(TENANT);
  assert.equal(route.payload.apiHost, `api-${TENANT}.femled.ai`);
  assert.equal(state.deployWebhookRoutes.size, 0);

  const headers = buildRouteProofHeaders(route);
  assert.equal(headers["X-Broker-Route-Digest"], envelope.payloadDigest);
  assert.equal(headers["X-Broker-Route-Key-Id"], "test-key");
  assert.equal(
    Buffer.from(headers["X-Broker-Route-Payload"], "base64url").toString("utf8"),
    canonicalStringify(envelope.payload)
  );
});

test("tenant route document derives trust anchor from TEE admission certificate", () => {
  const routeKeys = generateEd25519PemPair();
  const governance = createInMemoryGovernanceKeyMaterial();
  const admission = signTenantAdmissionCertificate({
    keyMaterial: governance,
    epoch: 1,
    lineageDigest: digestOf("lineage"),
    tenant: TENANT,
    tenantRouteSigningKeys: [
      {
        keyId: "tenant-route-key",
        alg: "Ed25519",
        publicKeyPem: routeKeys.publicPem,
      },
    ],
    minRouteVersion: 2,
    allowedApiHosts: [`api-${TENANT}.femled.ai`],
    allowedAppHosts: [`app-${TENANT}.femled.ai`],
    allowedBrokerAudiences: ["https://oauth-tee.femled.ai"],
    now: NOW,
  });
  const routeEnvelope = signRoute(tenantApiPayload(), routeKeys.privatePem, { keyId: "tenant-route-key" });
  const document = routeDocument({ admission, routeEnvelope });

  const state = buildRegistryState({
    trustAnchors: emptyTrustAnchors(),
    routeDocuments: [document],
    verifyAdmission: (envelope) => verifyGovernanceEnvelope(envelope, governance.governancePublicKeyPem),
    now: NOW,
  });

  const route = state.tenantApiRoutes.get(TENANT);
  assert.equal(route.payloadDigest, routeEnvelope.payloadDigest);
  assert.equal(route.admissionPayloadDigest, admission.payloadDigest);
  assert.equal(state.routeDocumentCount, 1);
});

test("tenant route document rejects routes outside admitted host policy", () => {
  const routeKeys = generateEd25519PemPair();
  const governance = createInMemoryGovernanceKeyMaterial();
  const admission = signTenantAdmissionCertificate({
    keyMaterial: governance,
    epoch: 1,
    lineageDigest: digestOf("lineage"),
    tenant: TENANT,
    tenantRouteSigningKeys: [
      {
        keyId: "tenant-route-key",
        alg: "Ed25519",
        publicKeyPem: routeKeys.publicPem,
      },
    ],
    minRouteVersion: 2,
    allowedApiHosts: ["api-other.femled.ai"],
    allowedAppHosts: [`app-${TENANT}.femled.ai`],
    allowedBrokerAudiences: ["https://oauth-tee.femled.ai"],
    now: NOW,
  });
  const routeEnvelope = signRoute(tenantApiPayload(), routeKeys.privatePem, { keyId: "tenant-route-key" });

  assert.throws(
    () => buildRegistryState({
      trustAnchors: emptyTrustAnchors(),
      routeDocuments: [routeDocument({ admission, routeEnvelope })],
      verifyAdmission: (envelope) => verifyGovernanceEnvelope(envelope, governance.governancePublicKeyPem),
      now: NOW,
    }),
    /apiHost is not admitted/
  );
});

test("Firestore tenant route documents and private deploy bundle load as separate sources", async () => {
  const keys = generateEd25519PemPair();
  const governance = createInMemoryGovernanceKeyMaterial();
  const admission = signTenantAdmissionCertificate({
    keyMaterial: governance,
    epoch: 1,
    lineageDigest: digestOf("lineage"),
    tenant: TENANT,
    tenantRouteSigningKeys: [
      {
        keyId: "tenant-route-key",
        alg: "Ed25519",
        publicKeyPem: keys.publicPem,
      },
    ],
    minRouteVersion: 2,
    allowedApiHosts: [`api-${TENANT}.femled.ai`],
    allowedAppHosts: [`app-${TENANT}.femled.ai`],
    allowedBrokerAudiences: ["https://oauth-tee.femled.ai"],
    now: NOW,
  });
  const tenantEnvelope = signRoute(tenantApiPayload(), keys.privatePem, { keyId: "tenant-route-key" });
  const deployEnvelope = signRoute(deployWebhookPayload(), keys.privatePem);

  const { initializeRouteRegistry, getTenantApiRoute, getDeployWebhookRouteForRepo } = await import("../src/route-registry.js");
  await initializeRouteRegistry({
    trustAnchors: trustAnchors(keys.publicPem),
    routeDocuments: [routeDocument({ admission, routeEnvelope: tenantEnvelope })],
    verifyAdmission: (envelope) => verifyGovernanceEnvelope(envelope, governance.governancePublicKeyPem),
    deployBundle: { schema: ROUTE_BUNDLE_SCHEMA, routes: [deployEnvelope] },
    refreshMs: 0,
    now: NOW,
  });

  assert.equal(getTenantApiRoute(TENANT).payload.schema, TENANT_API_ROUTE_SCHEMA);
  assert.equal(getDeployWebhookRouteForRepo("tenant-repo").payload.schema, DEPLOY_WEBHOOK_ROUTE_SCHEMA);
});

test("inactive startup can skip tenant route documents until activation", async () => {
  const {
    initializeRouteRegistry,
    getRouteRegistryStatus,
    getTenantApiRoute,
  } = await import("../src/route-registry.js");

  await initializeRouteRegistry({
    trustAnchors: emptyTrustAnchors(),
    routeDocuments: [{ invalid: "would fail if loaded" }],
    deployBundle: { schema: ROUTE_BUNDLE_SCHEMA, routes: [] },
    skipTenantRouteDocuments: true,
    refreshMs: 0,
    now: NOW,
  });

  assert.equal(getRouteRegistryStatus().routeDocumentCount, 0);
  assert.equal(getTenantApiRoute(TENANT), null);
});

test("ECDSA P-256 route signatures verify for tenant KMS-compatible keys", () => {
  const keys = generateP256PemPair();
  const envelope = signRouteEcdsa(tenantApiPayload(), keys.privatePem);
  const state = buildRegistryState({
    trustAnchors: trustAnchors(keys.publicPem, { alg: "ECDSA_P256_SHA256" }),
    bundle: { schema: ROUTE_BUNDLE_SCHEMA, routes: [envelope] },
    now: NOW,
  });

  assert.equal(state.tenantApiRoutes.get(TENANT).signature.alg, "ECDSA_P256_SHA256");
});

test("unsigned or wrong-key route records are rejected", () => {
  const keys = generateEd25519PemPair();
  const wrongKeys = generateEd25519PemPair();
  const envelope = signRoute(tenantApiPayload(), wrongKeys.privatePem);

  assert.throws(
    () => verifySignedRouteEnvelope(envelope, { trustAnchors: trustAnchors(keys.publicPem), now: NOW }),
    /signature verification failed/
  );
});

test("stale and downgraded route records are rejected", () => {
  const keys = generateEd25519PemPair();

  assert.throws(
    () => verifySignedRouteEnvelope(signRoute({
      ...tenantApiPayload(),
      expiresAt: "2026-05-05T11:59:59Z",
    }, keys.privatePem), { trustAnchors: trustAnchors(keys.publicPem), now: NOW }),
    /expired/
  );

  assert.throws(
    () => verifySignedRouteEnvelope(signRoute({
      ...tenantApiPayload(),
      version: 1,
    }, keys.privatePem), {
      trustAnchors: trustAnchors(keys.publicPem, { minRouteVersion: 2 }),
      now: NOW,
    }),
    /below minRouteVersion/
  );
});

test("route schemas cannot be confused between tenant API and deploy webhook use", () => {
  const keys = generateEd25519PemPair();
  const deployEnvelope = signRoute(deployWebhookPayload(), keys.privatePem);
  const state = buildRegistryState({
    trustAnchors: trustAnchors(keys.publicPem),
    bundle: { schema: ROUTE_BUNDLE_SCHEMA, routes: [deployEnvelope] },
    now: NOW,
  });

  assert.equal(state.tenantApiRoutes.size, 0);
  assert.equal(state.deployWebhookRoutes.get("tenant-repo").payload.cloudBuildDeployTriggerUrl, "https://cloudbuild.googleapis.com/v1/projects/example/triggers/trigger-id:webhook");
  assert.throws(
    () => buildRouteProofHeaders(state.deployWebhookRoutes.get("tenant-repo")),
    /tenant API route/
  );
});

function signRoute(payload, privatePem, { keyId = "test-key" } = {}) {
  return {
    payload,
    payloadDigest: sha256Digest(canonicalStringify(payload)),
    signature: {
      alg: "Ed25519",
      keyId,
      sig: signCanonicalPayload(payload, privatePem),
    },
  };
}

function signRouteEcdsa(payload, privatePem) {
  return {
    payload,
    payloadDigest: sha256Digest(canonicalStringify(payload)),
    signature: {
      alg: "ECDSA_P256_SHA256",
      keyId: "test-key",
      sig: crypto.sign("sha256", Buffer.from(canonicalStringify(payload), "utf8"), privatePem).toString("base64url"),
    },
  };
}

function routeDocument({ admission, routeEnvelope }) {
  return {
    schema: ROUTE_DOCUMENT_SCHEMA,
    admissionEnvelope: admission,
    routeEnvelope,
    sourceLegacyCoupleDigest: null,
    updatedAt: "2026-05-05T12:00:00Z",
  };
}

function tenantApiPayload() {
  return {
    schema: TENANT_API_ROUTE_SCHEMA,
    tenant: TENANT,
    version: 2,
    issuedAt: "2026-05-05T00:00:00Z",
    expiresAt: "2026-06-04T00:00:00Z",
    apiHost: `api-${TENANT}.femled.ai`,
    appHost: `app-${TENANT}.femled.ai`,
    allowedBrokerAudiences: ["https://oauth-tee.femled.ai"],
  };
}

function deployWebhookPayload() {
  return {
    schema: DEPLOY_WEBHOOK_ROUTE_SCHEMA,
    tenant: TENANT,
    version: 2,
    issuedAt: "2026-05-05T00:00:00Z",
    expiresAt: "2026-06-04T00:00:00Z",
    githubRepoName: "tenant-repo",
    cloudBuildDeployTriggerUrl: "https://cloudbuild.googleapis.com/v1/projects/example/triggers/trigger-id:webhook",
  };
}

function trustAnchors(publicKeyPem, { minRouteVersion = 1, alg = "Ed25519" } = {}) {
  return {
    schema: ROUTE_TRUST_ANCHORS_SCHEMA,
    tenants: {
      [TENANT]: {
        minRouteVersion,
        routeSigningKeys: [
          {
            keyId: "test-key",
            alg,
            publicKeyPem,
          },
        ],
      },
    },
  };
}

function emptyTrustAnchors() {
  return {
    schema: ROUTE_TRUST_ANCHORS_SCHEMA,
    tenants: {},
  };
}

function generateEd25519PemPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
  };
}

function generateP256PemPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
  };
}

function digestOf(value) {
  return sha256Digest(value);
}

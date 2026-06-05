import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalStringify,
  sha256Digest,
  verifyCanonicalPayload,
} from "./canonical-json.js";
import { getMetadataAccessToken, getProjectId } from "./gcp-auth.js";
import { recordRouteBundleRefresh } from "./governance-monitor.js";

export const ROUTE_TRUST_ANCHORS_SCHEMA = "femled.auth_broker.route_trust_anchors.v1";
export const ROUTE_BUNDLE_SCHEMA = "femled.auth_broker.route_bundle.v1";
export const ROUTE_DOCUMENT_SCHEMA = "femled.auth_broker.route_document.v1";
export const TENANT_API_ROUTE_SCHEMA = "femled.auth_broker.tenant_api_route.v1";
export const DEPLOY_WEBHOOK_ROUTE_SCHEMA = "femled.auth_broker.deploy_webhook_route.v1";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HOST_RE = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/;
const REPO_RE = /^[A-Za-z0-9._-]+$/;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_REFRESH_MS = 5 * 60 * 1000;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_TRUST_ANCHORS_PATH = path.join(__dirname, "route-trust-anchors.json");

let registryState = emptyRegistryState();
let refreshTimer = null;
let tenantAdmissionVerifier = null;
let acceptedRouteRecorder = null;

export function setTenantAdmissionVerifier(verifier) {
  tenantAdmissionVerifier = verifier;
}

export function setAcceptedRouteRecorder(recorder) {
  acceptedRouteRecorder = recorder;
}

export async function initializeRouteRegistry(options = {}) {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }

  const trustAnchors = options.trustAnchors || await loadTrustAnchors(options.trustAnchorsPath);
  const source = await loadRouteSources(options);
  registryState = buildRegistryState({
    trustAnchors,
    bundle: source.bundle,
    routeDocuments: source.routeDocuments,
    verifyAdmission: options.verifyAdmission || tenantAdmissionVerifier,
    now: options.now || new Date(),
    ignoreInvalidRouteDocuments: Boolean(options.ignoreInvalidRouteDocuments),
  });
  recordRouteBundleRefresh({ status: "success" });

  const refreshMs = Number(options.refreshMs || process.env.AUTH_BROKER_ROUTE_BUNDLE_REFRESH_MS || DEFAULT_REFRESH_MS);
  if (!options.skipTenantRouteDocuments && !options.bundle && !options.routeDocuments && refreshMs > 0 && hasConfiguredRouteSource()) {
    refreshTimer = setInterval(() => {
      refreshRouteRegistry({
        ignoreInvalidRouteDocuments: Boolean(options.ignoreInvalidRouteDocuments),
      }).catch((error) => {
        recordRouteBundleRefresh({ status: "failed", reason: error.message });
        console.error("[RouteRegistry] Refresh failed:", error.message);
      });
    }, refreshMs);
  }

  return getRouteRegistryStatus();
}

export async function refreshRouteRegistry(options = {}) {
  const trustAnchors = await loadTrustAnchors();
  const source = await loadRouteSources();
  registryState = buildRegistryState({
    trustAnchors,
    bundle: source.bundle,
    routeDocuments: source.routeDocuments,
    verifyAdmission: tenantAdmissionVerifier,
    now: new Date(),
    ignoreInvalidRouteDocuments: Boolean(options.ignoreInvalidRouteDocuments),
  });
  recordRouteBundleRefresh({ status: "success" });
  return getRouteRegistryStatus();
}

export function buildRegistryState({ trustAnchors, bundle, routeDocuments = [], verifyAdmission = null, now = new Date(), ignoreInvalidRouteDocuments = false }) {
  const normalizedAnchors = validateTrustAnchors(trustAnchors);
  const routes = Array.isArray(bundle?.routes) ? bundle.routes : [];
  if (bundle && bundle.schema !== ROUTE_BUNDLE_SCHEMA) {
    throw new Error(`route bundle schema must be ${ROUTE_BUNDLE_SCHEMA}`);
  }
  if (!Array.isArray(routeDocuments)) {
    throw new Error("routeDocuments must be an array");
  }

  const tenantApiRoutes = new Map();
  const deployWebhookRoutes = new Map();
  const routeSummaries = [];

  for (const document of routeDocuments) {
    try {
      const verified = verifyTenantRouteDocument(document, {
        verifyAdmission,
        now,
      });
      addVerifiedRoute({ verified, tenantApiRoutes, deployWebhookRoutes, routeSummaries, source: "firestore-route-document" });
    } catch (error) {
      if (!ignoreInvalidRouteDocuments) throw error;
      routeSummaries.push({
        schema: "femled.auth_broker.rejected_route_document.v1",
        tenant: null,
        version: null,
        digest: sha256Digest(canonicalStringify(document)),
        expiresAt: null,
        source: "firestore-route-document",
        rejected: true,
        reasonDigest: sha256Digest(error.message || "route document rejected"),
      });
    }
  }

  for (const envelope of routes) {
    const verified = verifySignedRouteEnvelope(envelope, {
      trustAnchors: normalizedAnchors,
      now,
    });
    addVerifiedRoute({ verified, tenantApiRoutes, deployWebhookRoutes, routeSummaries, source: "route-bundle" });
  }

  const bundleDigestInput = {
    schema: ROUTE_BUNDLE_SCHEMA,
    routes,
    routeDocuments,
  };
  return {
    initializedAt: new Date().toISOString(),
    trustAnchors: normalizedAnchors,
    trustAnchorsDigest: sha256Digest(canonicalStringify(normalizedAnchors.raw)),
    bundleDigest: sha256Digest(canonicalStringify(bundleDigestInput)),
    routeDocumentCount: routeDocuments.length,
    routeDocumentDigest: sha256Digest(canonicalStringify(routeDocuments)),
    tenantApiRoutes,
    deployWebhookRoutes,
    routeSummaries,
  };
}

export function verifySignedRouteEnvelope(envelope, { trustAnchors, now = new Date() } = {}) {
  const normalizedAnchors = trustAnchors?.tenants instanceof Map ? trustAnchors : validateTrustAnchors(trustAnchors);
  if (!envelope || typeof envelope !== "object") {
    throw new Error("route envelope must be an object");
  }
  assertExactKeys(envelope, ["payload", "payloadDigest", "signature"], "route envelope");
  if (!envelope.payload || typeof envelope.payload !== "object") {
    throw new Error("route envelope payload must be an object");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(envelope.payloadDigest || "")) {
    throw new Error("route envelope payloadDigest must be sha256:<hex>");
  }
  if (!envelope.signature || typeof envelope.signature !== "object") {
    throw new Error("route envelope signature must be an object");
  }
  assertExactKeys(envelope.signature, ["alg", "keyId", "sig"], "route signature");
  assertSupportedRouteAlgorithm(envelope.signature.alg);

  const payloadDigest = sha256Digest(canonicalStringify(envelope.payload));
  if (payloadDigest !== envelope.payloadDigest) {
    throw new Error("route payloadDigest does not match canonical payload");
  }

  const tenantAnchor = normalizedAnchors.tenants.get(envelope.payload.tenant);
  if (!tenantAnchor) {
    throw new Error(`no route trust anchor for tenant ${envelope.payload.tenant}`);
  }

  const key = tenantAnchor.routeSigningKeys.find((candidate) =>
    candidate.keyId === envelope.signature.keyId && candidate.alg === envelope.signature.alg
  );
  if (!key) {
    throw new Error(`no active route signing key ${envelope.signature.keyId} for tenant ${envelope.payload.tenant}`);
  }

  if (!verifyRouteSignature(envelope.payload, envelope.signature, key)) {
    throw new Error("route signature verification failed");
  }

  validateRoutePayload(envelope.payload, {
    minRouteVersion: tenantAnchor.minRouteVersion,
    now,
  });

  return {
    payload: envelope.payload,
    payloadDigest,
    signature: envelope.signature,
    canonicalPayload: canonicalStringify(envelope.payload),
  };
}

export function verifyTenantRouteDocument(document, { verifyAdmission, now = new Date() } = {}) {
  if (!verifyAdmission) {
    throw new Error("tenant route documents require an admission verifier");
  }
  if (!document || typeof document !== "object") {
    throw new Error("tenant route document must be an object");
  }
  assertExactKeys(
    document,
    ["admissionEnvelope", "routeEnvelope", "schema", "sourceLegacyCoupleDigest", "updatedAt"],
    "tenant route document"
  );
  if (document.schema !== ROUTE_DOCUMENT_SCHEMA) {
    throw new Error(`tenant route document schema must be ${ROUTE_DOCUMENT_SCHEMA}`);
  }
  const admission = verifyAdmission(document.admissionEnvelope, { now });
  const anchors = routeTrustAnchorsFromAdmission(admission);
  const verified = verifySignedRouteEnvelope(document.routeEnvelope, { trustAnchors: anchors, now });
  if (verified.payload.tenant !== admission.tenant) {
    throw new Error("route document tenant mismatch between admission and route envelope");
  }
  enforceAdmissionRoutePolicy(admission, verified.payload);
  if (acceptedRouteRecorder && verified.payload.schema === TENANT_API_ROUTE_SCHEMA) {
    acceptedRouteRecorder({
      tenant: verified.payload.tenant,
      routeVersion: verified.payload.version,
      routeDigest: verified.payloadDigest,
    });
  }
  return {
    ...verified,
    admission,
    admissionPayloadDigest: document.admissionEnvelope.payloadDigest,
    routeDocumentDigest: sha256Digest(canonicalStringify(document)),
  };
}

export function getTenantApiRoute(tenant) {
  return registryState.tenantApiRoutes.get(tenant) || null;
}

export function getDeployWebhookRouteForRepo(repoName) {
  return registryState.deployWebhookRoutes.get(repoName) || null;
}

export function buildRouteProofHeaders(verifiedRoute) {
  if (!verifiedRoute?.payload || verifiedRoute.payload.schema !== TENANT_API_ROUTE_SCHEMA) {
    throw new Error("route proof headers require a tenant API route");
  }
  return {
    "X-Broker-Route-Digest": verifiedRoute.payloadDigest,
    "X-Broker-Route-Version": String(verifiedRoute.payload.version),
    "X-Broker-Route-Key-Id": verifiedRoute.signature.keyId,
    "X-Broker-Route-Signature": verifiedRoute.signature.sig,
    "X-Broker-Route-Payload": Buffer.from(verifiedRoute.canonicalPayload, "utf8").toString("base64url"),
  };
}

export function getRouteRegistryStatus() {
  return {
    initializedAt: registryState.initializedAt,
    trustAnchorsDigest: registryState.trustAnchorsDigest,
    routeBundleDigest: registryState.bundleDigest,
    routeDocumentCount: registryState.routeDocumentCount,
    routeDocumentDigest: registryState.routeDocumentDigest,
    tenantApiRouteCount: registryState.tenantApiRoutes.size,
    deployWebhookRouteCount: registryState.deployWebhookRoutes.size,
    routeSummaries: registryState.routeSummaries,
  };
}

async function loadTrustAnchors(configuredPath) {
  const trustAnchorsPath = configuredPath || process.env.AUTH_BROKER_ROUTE_TRUST_ANCHORS_PATH || DEFAULT_TRUST_ANCHORS_PATH;
  const raw = await fs.readFile(trustAnchorsPath, "utf8");
  return JSON.parse(raw);
}

async function loadRouteSources(options = {}) {
  const deployBundle = await loadPrivateDeployRouteBundle(options);
  const routeDocuments = options.skipTenantRouteDocuments
    ? []
    : await loadFirestoreRouteDocuments(options);
  return {
    bundle: {
      schema: ROUTE_BUNDLE_SCHEMA,
      routes: [
        ...deployBundle.routes,
      ],
    },
    routeDocuments,
  };
}

async function loadPrivateDeployRouteBundle(options = {}) {
  if (options.deployBundle) return options.deployBundle;
  const deployPath = options.deployBundlePath || process.env.AUTH_BROKER_DEPLOY_ROUTE_BUNDLE_PATH;
  const deployUrl = options.deployBundleUrl || process.env.AUTH_BROKER_DEPLOY_ROUTE_BUNDLE_URL;
  const deployJson = options.deployBundleJson || process.env.AUTH_BROKER_DEPLOY_ROUTE_BUNDLE_JSON;

  if (deployPath) {
    return assertBundle(JSON.parse(await fs.readFile(deployPath, "utf8")), "private deploy route bundle");
  }
  if (deployJson) {
    return assertBundle(JSON.parse(deployJson), "private deploy route bundle");
  }
  if (deployUrl) {
    const response = await fetch(deployUrl, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) {
      throw new Error(`private deploy route bundle fetch failed (${response.status})`);
    }
    return assertBundle(await response.json(), "private deploy route bundle");
  }
  return emptyBundle();
}

async function loadFirestoreRouteDocuments(options = {}) {
  if (options.routeDocuments) return options.routeDocuments;
  const collectionPath = options.firestoreRouteCollection || process.env.AUTH_BROKER_ROUTE_FIRESTORE_COLLECTION;
  if (!collectionPath) return [];
  const accessToken = await getMetadataAccessToken();
  if (!accessToken) throw new Error("Firestore route document loading requires metadata access token");
  const projectId = getProjectId();
  const documents = [];
  let pageToken = "";
  do {
    const url = new URL(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collectionPath}`);
    url.searchParams.set("pageSize", "1000");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) {
      throw new Error(`Firestore route document fetch failed (${response.status})`);
    }
    const body = await response.json();
    for (const document of body.documents || []) {
      documents.push(decodeFirestoreDocument(document));
    }
    pageToken = body.nextPageToken || "";
  } while (pageToken);
  return documents;
}

function hasConfiguredRouteSource() {
  return Boolean(
    process.env.AUTH_BROKER_DEPLOY_ROUTE_BUNDLE_URL ||
    process.env.AUTH_BROKER_DEPLOY_ROUTE_BUNDLE_PATH ||
    process.env.AUTH_BROKER_DEPLOY_ROUTE_BUNDLE_JSON ||
    process.env.AUTH_BROKER_ROUTE_FIRESTORE_COLLECTION
  );
}

function assertBundle(bundle, label) {
  if (!bundle || bundle.schema !== ROUTE_BUNDLE_SCHEMA || !Array.isArray(bundle.routes)) {
    throw new Error(`${label} must have schema ${ROUTE_BUNDLE_SCHEMA} and routes[]`);
  }
  return bundle;
}

function emptyBundle() {
  return { schema: ROUTE_BUNDLE_SCHEMA, routes: [] };
}

function validateTrustAnchors(value) {
  if (!value || typeof value !== "object") {
    throw new Error("route trust anchors must be an object");
  }
  assertExactKeys(value, ["schema", "tenants"], "route trust anchors");
  if (value.schema !== ROUTE_TRUST_ANCHORS_SCHEMA) {
    throw new Error(`route trust anchors schema must be ${ROUTE_TRUST_ANCHORS_SCHEMA}`);
  }
  if (!value.tenants || typeof value.tenants !== "object" || Array.isArray(value.tenants)) {
    throw new Error("route trust anchors tenants must be an object");
  }

  const tenants = new Map();
  for (const [tenant, body] of Object.entries(value.tenants)) {
    if (!UUID_RE.test(tenant)) {
      throw new Error(`invalid tenant id in route trust anchors: ${tenant}`);
    }
    assertExactKeys(body, ["minRouteVersion", "routeSigningKeys"], `route trust anchor ${tenant}`);
    if (!Number.isInteger(body.minRouteVersion) || body.minRouteVersion < 1) {
      throw new Error(`minRouteVersion for ${tenant} must be a positive integer`);
    }
    if (!Array.isArray(body.routeSigningKeys) || body.routeSigningKeys.length === 0) {
      throw new Error(`routeSigningKeys for ${tenant} must be a non-empty array`);
    }
    const seenKeyIds = new Set();
    for (const key of body.routeSigningKeys) {
      assertExactKeys(key, ["alg", "keyId", "publicKeyPem"], `route signing key ${tenant}`);
      assertSupportedRouteAlgorithm(key.alg);
      if (!key.keyId || typeof key.keyId !== "string") throw new Error(`route signing key for ${tenant} needs keyId`);
      if (seenKeyIds.has(key.keyId)) throw new Error(`duplicate route signing key ${key.keyId} for ${tenant}`);
      seenKeyIds.add(key.keyId);
      if (typeof key.publicKeyPem !== "string" || !key.publicKeyPem.includes("BEGIN PUBLIC KEY")) {
        throw new Error(`route signing key ${tenant}/${key.keyId} must include a public key PEM`);
      }
    }
    tenants.set(tenant, body);
  }

  return { raw: value, tenants };
}

function addVerifiedRoute({ verified, tenantApiRoutes, deployWebhookRoutes, routeSummaries, source }) {
  if (verified.payload.schema === TENANT_API_ROUTE_SCHEMA) {
    assertUnique(tenantApiRoutes, verified.payload.tenant, "tenant API route");
    tenantApiRoutes.set(verified.payload.tenant, verified);
  } else if (verified.payload.schema === DEPLOY_WEBHOOK_ROUTE_SCHEMA) {
    assertUnique(deployWebhookRoutes, verified.payload.githubRepoName, "deployment webhook route");
    deployWebhookRoutes.set(verified.payload.githubRepoName, verified);
  } else {
    throw new Error(`unsupported route schema: ${verified.payload.schema}`);
  }
  routeSummaries.push({
    schema: verified.payload.schema,
    tenant: verified.payload.tenant,
    version: verified.payload.version,
    digest: verified.payloadDigest,
    expiresAt: verified.payload.expiresAt,
    source,
  });
}

function routeTrustAnchorsFromAdmission(admission) {
  return {
    schema: ROUTE_TRUST_ANCHORS_SCHEMA,
    tenants: {
      [admission.tenant]: {
        minRouteVersion: admission.minRouteVersion,
        routeSigningKeys: admission.tenantRouteSigningKeys.map((key) => ({
          alg: key.alg,
          keyId: key.keyId,
          publicKeyPem: key.publicKeyPem,
        })),
      },
    },
  };
}

function enforceAdmissionRoutePolicy(admission, payload) {
  if (payload.schema === TENANT_API_ROUTE_SCHEMA) {
    if (!admission.allowedApiHosts.includes(payload.apiHost)) {
      throw new Error("tenant API route apiHost is not admitted by TEE policy");
    }
    if (!admission.allowedAppHosts.includes(payload.appHost)) {
      throw new Error("tenant API route appHost is not admitted by TEE policy");
    }
    for (const audience of payload.allowedBrokerAudiences || []) {
      if (!admission.allowedBrokerAudiences.includes(audience)) {
        throw new Error("tenant API route audience is not admitted by TEE policy");
      }
    }
  }
}

function verifyRouteSignature(payload, signature, key) {
  if (signature.alg !== key.alg) return false;
  if (signature.alg === "Ed25519") {
    return verifyCanonicalPayload(payload, signature.sig, key.publicKeyPem);
  }
  if (signature.alg === "ECDSA_P256_SHA256") {
    return crypto.verify(
      "sha256",
      Buffer.from(canonicalStringify(payload), "utf8"),
      crypto.createPublicKey(key.publicKeyPem),
      Buffer.from(signature.sig, "base64url")
    );
  }
  return false;
}

function assertSupportedRouteAlgorithm(alg) {
  if (!["Ed25519", "ECDSA_P256_SHA256"].includes(alg)) {
    throw new Error("route signature alg must be Ed25519 or ECDSA_P256_SHA256");
  }
}

function decodeFirestoreDocument(document) {
  const decoded = decodeFirestoreFields(document.fields || {});
  if (typeof decoded.documentJson === "string") {
    return JSON.parse(decoded.documentJson);
  }
  return decoded;
}

function decodeFirestoreFields(fields) {
  const out = {};
  for (const [key, value] of Object.entries(fields || {})) {
    out[key] = decodeFirestoreValue(value);
  }
  return out;
}

function decodeFirestoreValue(value) {
  if (!value || typeof value !== "object") return null;
  if ("stringValue" in value) return value.stringValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("booleanValue" in value) return Boolean(value.booleanValue);
  if ("timestampValue" in value) return value.timestampValue;
  if ("nullValue" in value) return null;
  if ("arrayValue" in value) return (value.arrayValue.values || []).map(decodeFirestoreValue);
  if ("mapValue" in value) return decodeFirestoreFields(value.mapValue.fields || {});
  throw new Error("unsupported Firestore value in route document");
}

function validateRoutePayload(payload, { minRouteVersion, now }) {
  const commonKeys = ["expiresAt", "issuedAt", "schema", "tenant", "version"];
  if (payload.schema === TENANT_API_ROUTE_SCHEMA) {
    assertExactKeys(payload, [...commonKeys, "allowedBrokerAudiences", "apiHost", "appHost"], "tenant API route payload");
    validateTenantApiRoute(payload);
  } else if (payload.schema === DEPLOY_WEBHOOK_ROUTE_SCHEMA) {
    assertExactKeys(payload, [...commonKeys, "cloudBuildDeployTriggerUrl", "githubRepoName"], "deployment webhook route payload");
    validateDeployWebhookRoute(payload);
  } else {
    throw new Error(`unsupported route schema: ${payload.schema}`);
  }

  if (!UUID_RE.test(payload.tenant || "")) throw new Error("route tenant must be a UUID");
  if (!Number.isInteger(payload.version) || payload.version < 1) throw new Error("route version must be a positive integer");
  if (payload.version < minRouteVersion) throw new Error("route version is below minRouteVersion");

  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(issuedAt)) throw new Error("route issuedAt must be an ISO timestamp");
  if (!Number.isFinite(expiresAt)) throw new Error("route expiresAt must be an ISO timestamp");
  if (issuedAt > nowMs + CLOCK_SKEW_MS) throw new Error("route issuedAt is too far in the future");
  if (expiresAt <= nowMs) throw new Error("route is expired");
}

function validateTenantApiRoute(payload) {
  validateHost(payload.apiHost, "apiHost");
  validateHost(payload.appHost, "appHost");
  if (!payload.apiHost.startsWith("api-") || !payload.apiHost.endsWith(".femled.ai")) {
    throw new Error("apiHost must be an api-*.femled.ai hostname");
  }
  if (!payload.appHost.startsWith("app-") || !payload.appHost.endsWith(".femled.ai")) {
    throw new Error("appHost must be an app-*.femled.ai hostname");
  }
  if (!Array.isArray(payload.allowedBrokerAudiences) || !payload.allowedBrokerAudiences.includes("https://oauth-tee.femled.ai")) {
    throw new Error("allowedBrokerAudiences must include https://oauth-tee.femled.ai");
  }
}

function validateDeployWebhookRoute(payload) {
  if (!REPO_RE.test(payload.githubRepoName || "")) {
    throw new Error("githubRepoName must be a safe GitHub repo name");
  }
  let parsed;
  try {
    parsed = new URL(payload.cloudBuildDeployTriggerUrl);
  } catch {
    throw new Error("cloudBuildDeployTriggerUrl must be a valid URL");
  }
  if (parsed.protocol !== "https:") throw new Error("cloudBuildDeployTriggerUrl must use HTTPS");
  if (parsed.hostname !== "cloudbuild.googleapis.com") {
    throw new Error("cloudBuildDeployTriggerUrl must target cloudbuild.googleapis.com");
  }
}

function validateHost(value, field) {
  if (typeof value !== "string" || value.length > 253 || !HOST_RE.test(value)) {
    throw new Error(`${field} must be a hostname`);
  }
  if (value.includes("/") || value.includes(":") || value.includes("@") || value.includes("?") || value.includes("#")) {
    throw new Error(`${field} must not include URL syntax`);
  }
}

function assertExactKeys(value, keys, label) {
  const expected = [...keys].sort();
  const actual = Object.keys(value || {}).sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
    throw new Error(`${label} keys must be exactly: ${expected.join(", ")}`);
  }
}

function assertUnique(map, key, label) {
  if (map.has(key)) {
    throw new Error(`duplicate ${label} for ${key}`);
  }
}

function emptyRegistryState() {
  return {
    initializedAt: null,
    trustAnchors: { raw: { schema: ROUTE_TRUST_ANCHORS_SCHEMA, tenants: {} }, tenants: new Map() },
    trustAnchorsDigest: sha256Digest(canonicalStringify({ schema: ROUTE_TRUST_ANCHORS_SCHEMA, tenants: {} })),
    bundleDigest: sha256Digest(canonicalStringify({ schema: ROUTE_BUNDLE_SCHEMA, routes: [] })),
    tenantApiRoutes: new Map(),
    deployWebhookRoutes: new Map(),
    routeSummaries: [],
    routeDocumentCount: 0,
    routeDocumentDigest: sha256Digest(canonicalStringify([])),
  };
}

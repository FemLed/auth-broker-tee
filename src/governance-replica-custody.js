// Two-replica custody of the in-enclave governance key.
//
// A primary and a custodian replica of the same image hold one lineage key.
// The primary serves; the custodian keeps a current copy so that a restarted
// replica can be re-keyed instead of the lineage being lost. Losing both means
// operator re-genesis.
//
// Custody is pulled by the replica that needs it. It presents a key-bound
// attestation: a Confidential Space token whose nonce this enclave computed over
// its own key ids, answering a challenge the live replica issued. The live
// replica seals the lineage key and state to that attested activation key, signs
// the bundle with the lineage key, and attests the bundle digest the same way,
// so the recipient can check where it came from. Nobody outside the two
// enclaves ever holds a usable copy of the key.
//
// Every governance change the primary releases has first been acknowledged by
// the custodian (the replicator below runs inside each commit), so whichever
// replica survives holds everything that was released.

import crypto from "node:crypto";
import { canonicalStringify, publicKeyFingerprint, sha256Digest } from "./canonical-json.js";
import { requestAttestationToken } from "./attestation.js";
import { verifyConfidentialSpaceAttestation } from "./confidential-space-attestation.js";
import { signGovernancePayload, verifyGovernanceEnvelope } from "./governance-crypto.js";
import {
  applyReplicaCustodyTransfer,
  applyReplicaSync,
  buildReplicaCustodyTransfer,
  buildReplicaSync,
  getGovernanceState,
  getReplicaHealth,
  getReplicaPeer,
  getReplicaRole,
  isGovernanceKeyHolder,
  onGovernanceStateChange,
  promoteReplicaToPrimary,
  recordReplicaHealth,
  recordReplicaPeer,
  replicateGovernanceState,
} from "./governance-state.js";

export const REPLICA_CUSTODY_AUDIENCE = "https://oauth-tee.femled.ai/replica-custody";
const KEY_ATTESTATION_SCHEMA = "femled.auth_broker.replica_key_attestation.v1";
const CUSTODY_BUNDLE_SCHEMA = "femled.auth_broker.replica_custody_bundle.v1";
const SYNC_BUNDLE_SCHEMA = "femled.auth_broker.replica_sync_bundle.v1";
const HEARTBEAT_SCHEMA = "femled.auth_broker.replica_heartbeat.v1";
const REPLICA_MANIFEST_SCHEMA = "femled.auth_broker.replica_manifest.v1";
const EXPECTED_PROJECT_ID = "prod-femled-couple-router";
const EXPECTED_PROJECT_NUMBER = "125139120897";
const EXPECTED_SERVICE_ACCOUNT = "auth-broker-tee@prod-femled-couple-router.iam.gserviceaccount.com";
const REPLICA_INSTANCE_PREFIX = "auth-broker-tee-";
const CUSTODY_PORT = 8080;
const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const MAX_OPEN_CHALLENGES = 32;
const BUNDLE_TTL_MS = 2 * 60 * 1000;
const SUPERVISOR_INTERVAL_MS = 20 * 1000;
const PEER_TIMEOUT_MS = 15 * 1000;
// A primary heartbeats every supervisor tick; a custodian that has heard
// nothing from it for this long may be promoted.
export const PROMOTION_QUIET_MS = 3 * 60 * 1000;
const PROMOTION_PROBES = 3;
const PROMOTION_PROBE_INTERVAL_MS = 5 * 1000;

let verifyAttestation = verifyConfidentialSpaceAttestation;
let requestToken = requestAttestationToken;
let fetchPeer = (url, options) => fetch(url, options);
let sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let custodyNow = () => new Date();
const openChallenges = new Map();
let backgroundSyncDue = false;
let supervisorTimer = null;
let unsubscribeStateChanges = null;

// Launch metadata only locates the peer; it grants nothing, since every
// transfer is checked against the peer's attestation.
export function replicaConfig(env = process.env) {
  return {
    bootRole: env.REPLICA_ROLE === "custodian" ? "custodian" : "primary",
    peerUrl: env.REPLICA_PEER_URL ? String(env.REPLICA_PEER_URL).replace(/\/+$/, "") : null,
    peerInstance: env.REPLICA_PEER_INSTANCE || null,
  };
}

function keyAttestationNonce({ purpose, challenge, governanceKeyId, activationKeyId, imageDigest }) {
  return sha256Digest(canonicalStringify({
    schema: KEY_ATTESTATION_SCHEMA,
    purpose,
    challenge,
    governanceKeyId,
    activationKeyId,
    imageDigest,
  }));
}

// The nonce is computed here over this enclave's own key ids, and the token
// carries an audience /attestation never requests, so the token cannot be
// paired with keys the enclave does not hold.
export async function buildKeyAttestation({ purpose, challenge }) {
  const current = getGovernanceState();
  const { keyMaterial, imageDigest } = current;
  const nonce = keyAttestationNonce({
    purpose,
    challenge,
    governanceKeyId: keyMaterial.governanceKeyId,
    activationKeyId: keyMaterial.activationKeyId,
    imageDigest,
  });
  return {
    schema: KEY_ATTESTATION_SCHEMA,
    purpose,
    challenge,
    imageDigest,
    governancePublicKeyPem: keyMaterial.governancePublicKeyPem,
    activationPublicKeyPem: keyMaterial.activationPublicKeyPem,
    attestationToken: await requestToken([nonce], { audience: REPLICA_CUSTODY_AUDIENCE }),
  };
}

export async function verifyKeyAttestation(evidence, { purpose, challenge, expectedImageDigest, expectedInstance = null }) {
  if (evidence?.schema !== KEY_ATTESTATION_SCHEMA || evidence.purpose !== purpose || !challenge || evidence.challenge !== challenge) {
    throw new Error(`replica key attestation does not answer this ${purpose} challenge`);
  }
  if (evidence.imageDigest !== expectedImageDigest) {
    throw new Error("replica key attestation is for a different image");
  }
  const governanceKeyId = `sha256:${publicKeyFingerprint(evidence.governancePublicKeyPem)}`;
  const activationKeyId = `sha256:${publicKeyFingerprint(evidence.activationPublicKeyPem)}`;
  const claims = await verifyAttestation(evidence.attestationToken, {
    expectedNonce: keyAttestationNonce({ purpose, challenge, governanceKeyId, activationKeyId, imageDigest: evidence.imageDigest }),
    expectedImageDigest,
    expectedAudience: REPLICA_CUSTODY_AUDIENCE,
  });
  return {
    governanceKeyId,
    activationKeyId,
    governancePublicKeyPem: evidence.governancePublicKeyPem,
    activationPublicKeyPem: evidence.activationPublicKeyPem,
    instanceName: assertReplicaClaims(claims, { expectedInstance }),
  };
}

function assertReplicaClaims(claims, { expectedInstance }) {
  const gce = claims?.submods?.gce || {};
  if (gce.project_id !== EXPECTED_PROJECT_ID || String(gce.project_number ?? "") !== EXPECTED_PROJECT_NUMBER) {
    throw new Error("replica attestation is from another project");
  }
  if (!(claims.google_service_accounts || []).includes(EXPECTED_SERVICE_ACCOUNT)) {
    throw new Error("replica attestation does not run as the broker service account");
  }
  if (!(claims.submods?.confidential_space?.support_attributes || []).includes("STABLE")) {
    throw new Error("replica attestation lacks STABLE Confidential Space support");
  }
  const instanceName = String(gce.instance_name || "");
  if (!instanceName.startsWith(REPLICA_INSTANCE_PREFIX)) {
    throw new Error("replica attestation is not from a broker instance");
  }
  if (expectedInstance && instanceName !== expectedInstance) {
    throw new Error(`replica attestation is from ${instanceName}, not the configured peer ${expectedInstance}`);
  }
  return instanceName;
}

export function issueCustodyChallenge({ now = custodyNow().getTime() } = {}) {
  if (!isGovernanceKeyHolder()) throw new Error("this replica does not hold the lineage key");
  for (const [value, expiresAt] of openChallenges) {
    if (expiresAt <= now) openChallenges.delete(value);
  }
  if (openChallenges.size >= MAX_OPEN_CHALLENGES) throw new Error("too many open custody challenges");
  const challenge = crypto.randomBytes(32).toString("base64url");
  openChallenges.set(challenge, now + CHALLENGE_TTL_MS);
  return { challenge, expiresAt: new Date(now + CHALLENGE_TTL_MS).toISOString() };
}

function consumeCustodyChallenge(challenge, now) {
  const expiresAt = openChallenges.get(challenge);
  openChallenges.delete(challenge);
  if (!expiresAt || expiresAt <= now) throw new Error("unknown or expired custody challenge");
}

// Live side: re-keys the configured peer. The new replica takes the role
// opposite this one's, so a restarted primary comes back as primary.
export async function serveCustodyRequest({ challenge, evidence, requesterAddress = null }, { config = replicaConfig(), now = custodyNow() } = {}) {
  if (!isGovernanceKeyHolder()) throw new Error("this replica does not hold the lineage key");
  consumeCustodyChallenge(challenge, now.getTime());
  if (!config.peerInstance) throw new Error("this replica has no configured peer to re-key");
  const current = getGovernanceState();
  const recipient = await verifyKeyAttestation(evidence, {
    purpose: "custody-request",
    challenge,
    expectedImageDigest: current.imageDigest,
    expectedInstance: config.peerInstance,
  });
  const role = (getReplicaRole() || config.bootRole) === "primary" ? "custodian" : "primary";
  const aad = {
    schema: CUSTODY_BUNDLE_SCHEMA,
    lineageDigest: sha256Digest(canonicalStringify(current.lineage)),
    epoch: current.epoch,
    imageDigest: current.imageDigest,
    challenge,
    role,
    recipientInstance: recipient.instanceName,
    recipientActivationKeyId: recipient.activationKeyId,
    senderActivationKeyId: current.keyMaterial.activationKeyId,
    replicaSerial: current.replicaSerial || 0,
  };
  const encryptedState = await buildReplicaCustodyTransfer({ recipientActivationPublicKeyPem: recipient.activationPublicKeyPem, aad });
  const bundle = await signGovernancePayload({
    schema: CUSTODY_BUNDLE_SCHEMA,
    aad,
    encryptedState,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + BUNDLE_TTL_MS).toISOString(),
  }, current.keyMaterial);
  const senderAttestation = await buildKeyAttestation({ purpose: "custody-send", challenge: bundle.payloadDigest });
  recordReplicaPeer({
    instanceName: recipient.instanceName,
    activationPublicKeyPem: recipient.activationPublicKeyPem,
    activationKeyId: recipient.activationKeyId,
    role,
    syncUrl: syncUrlFor(requesterAddress) || config.peerUrl,
  });
  recordReplicaHealth({ lastAcknowledgedAt: now.toISOString(), peerSerial: aad.replicaSerial, lastError: null });
  return { bundle, senderAttestation };
}

// Recipient side: a fresh inactive replica asks its configured peer for custody.
export async function pullCustodyFromPeer({ config = replicaConfig(), now = custodyNow() } = {}) {
  const current = getGovernanceState();
  if (!config.peerUrl || current.status !== "inactive" || current.lineage.length > 0) return null;
  const { challenge } = await peerJson(`${config.peerUrl}/replica/custody-challenge`);
  const evidence = await buildKeyAttestation({ purpose: "custody-request", challenge });
  const response = await peerJson(`${config.peerUrl}/replica/custody-request`, {
    method: "POST",
    body: { challenge, evidence },
  });
  const bundle = response?.bundle;
  const sender = await verifyKeyAttestation(response?.senderAttestation, {
    purpose: "custody-send",
    challenge: bundle?.payloadDigest,
    expectedImageDigest: current.imageDigest,
    expectedInstance: config.peerInstance,
  });
  const payload = verifyGovernanceEnvelope(bundle, sender.governancePublicKeyPem, { now });
  const aad = payload.aad || {};
  if (payload.schema !== CUSTODY_BUNDLE_SCHEMA || aad.schema !== CUSTODY_BUNDLE_SCHEMA) {
    throw new Error("replica custody bundle schema mismatch");
  }
  if (aad.challenge !== challenge
    || aad.imageDigest !== current.imageDigest
    || aad.recipientActivationKeyId !== current.keyMaterial.activationKeyId
    || aad.senderActivationKeyId !== sender.activationKeyId) {
    throw new Error("replica custody bundle is not bound to this request");
  }
  const manifest = await applyReplicaCustodyTransfer({
    encryptedState: payload.encryptedState,
    aad,
    role: aad.role,
    expectedGovernanceKeyId: sender.governanceKeyId,
    now,
  });
  recordReplicaPeer({
    instanceName: sender.instanceName,
    activationPublicKeyPem: sender.activationPublicKeyPem,
    activationKeyId: sender.activationKeyId,
    role: aad.role === "primary" ? "custodian" : "primary",
    syncUrl: config.peerUrl,
  });
  recordReplicaHealth(aad.role === "custodian"
    ? { lastPrimaryContactAt: now.toISOString(), lastError: null }
    : { lastAcknowledgedAt: now.toISOString(), peerSerial: aad.replicaSerial, lastError: null });
  return manifest;
}

// The replicator: runs inside every commit on this replica and throws unless
// the custodian acknowledged the new state. A replica that is not the primary,
// or a primary whose custodian has not enrolled yet, has nobody to replicate to.
export async function replicateToCustodian() {
  const peer = getReplicaPeer();
  if (getReplicaRole() !== "primary" || !peer?.syncUrl || !peer.activationPublicKeyPem) return;
  try {
    await pushSyncToPeer();
  } catch (error) {
    recordReplicaHealth({ lastError: error.message });
    throw new Error(`governance change was not acknowledged by the custodian: ${error.message}`);
  }
}

async function pushSyncToPeer({ now = custodyNow() } = {}) {
  const current = getGovernanceState();
  const peer = getReplicaPeer();
  const aad = {
    schema: SYNC_BUNDLE_SCHEMA,
    lineageDigest: sha256Digest(canonicalStringify(current.lineage)),
    epoch: current.epoch,
    imageDigest: current.imageDigest,
    replicaSerial: current.replicaSerial || 0,
    recipientActivationKeyId: peer.activationKeyId,
  };
  const encryptedState = buildReplicaSync({ recipientActivationPublicKeyPem: peer.activationPublicKeyPem, aad });
  const bundle = await signGovernancePayload({
    schema: SYNC_BUNDLE_SCHEMA,
    aad,
    encryptedState,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + BUNDLE_TTL_MS).toISOString(),
  }, current.keyMaterial);
  const acknowledged = await peerJson(`${peer.syncUrl}/replica/sync`, { method: "POST", body: { bundle } });
  if (acknowledged?.replicaSerial !== aad.replicaSerial) {
    throw new Error(`custodian acknowledged serial ${acknowledged?.replicaSerial}, not ${aad.replicaSerial}`);
  }
  recordReplicaHealth({ lastAcknowledgedAt: now.toISOString(), peerSerial: aad.replicaSerial, lastError: null });
}

// Custodian side: the bundle must be signed by the lineage key this custodian
// holds and addressed to its own activation key.
export async function receiveSyncBundle({ bundle }, { now = custodyNow() } = {}) {
  const current = getGovernanceState();
  if (getReplicaRole() !== "custodian") throw new Error("only a custodian accepts replica state sync");
  const payload = verifyGovernanceEnvelope(bundle, current.keyMaterial.governancePublicKeyPem, { now });
  const aad = payload.aad || {};
  if (payload.schema !== SYNC_BUNDLE_SCHEMA || aad.schema !== SYNC_BUNDLE_SCHEMA) {
    throw new Error("replica sync bundle schema mismatch");
  }
  if (aad.imageDigest !== current.imageDigest || aad.recipientActivationKeyId !== current.keyMaterial.activationKeyId) {
    throw new Error("replica sync is not addressed to this custodian");
  }
  const result = await applyReplicaSync({ encryptedState: payload.encryptedState, aad, now });
  recordReplicaHealth({ lastPrimaryContactAt: now.toISOString(), peerSerial: result.replicaSerial, lastError: null });
  return result;
}

// Primary side of liveness: a signed heartbeat tells the custodian the primary
// is alive, and the reply shows whether the custodian is current.
export async function sendHeartbeatToPeer({ now = custodyNow() } = {}) {
  const current = getGovernanceState();
  const peer = getReplicaPeer();
  if (getReplicaRole() !== "primary" || !peer?.syncUrl || !peer.activationKeyId) return null;
  const heartbeat = await signGovernancePayload({
    schema: HEARTBEAT_SCHEMA,
    imageDigest: current.imageDigest,
    lineageDigest: sha256Digest(canonicalStringify(current.lineage)),
    replicaSerial: current.replicaSerial || 0,
    recipientActivationKeyId: peer.activationKeyId,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + BUNDLE_TTL_MS).toISOString(),
  }, current.keyMaterial);
  const reply = await peerJson(`${peer.syncUrl}/replica/heartbeat`, { method: "POST", body: { heartbeat } });
  recordReplicaHealth({ lastAcknowledgedAt: now.toISOString(), peerSerial: reply?.replicaSerial ?? null, lastError: null });
  if ((reply?.replicaSerial ?? -1) < (current.replicaSerial || 0)) backgroundSyncDue = true;
  return reply;
}

export function receiveHeartbeat({ heartbeat }, { now = custodyNow() } = {}) {
  const current = getGovernanceState();
  if (getReplicaRole() !== "custodian") throw new Error("only a custodian accepts replica heartbeats");
  const payload = verifyGovernanceEnvelope(heartbeat, current.keyMaterial.governancePublicKeyPem, { now });
  if (payload.schema !== HEARTBEAT_SCHEMA
    || payload.imageDigest !== current.imageDigest
    || payload.recipientActivationKeyId !== current.keyMaterial.activationKeyId) {
    throw new Error("replica heartbeat is not addressed to this custodian");
  }
  recordReplicaHealth({ lastPrimaryContactAt: now.toISOString() });
  return { status: current.status, replicaSerial: current.replicaSerial || 0 };
}

// Explicit failover. Refused unless the primary has been silent for the quiet
// period and does not answer as an active primary on any probe, because two
// primaries would split governance.
export async function promoteToPrimary({ config = replicaConfig(), now = custodyNow() } = {}) {
  if (getReplicaRole() !== "custodian") throw new Error("only a custodian can be promoted");
  const lastContact = Date.parse(getReplicaHealth().lastPrimaryContactAt || "") || 0;
  const silentForMs = now.getTime() - lastContact;
  if (silentForMs < PROMOTION_QUIET_MS) {
    throw new Error(`the primary was heard from ${Math.round(silentForMs / 1000)}s ago; promotion is allowed after ${PROMOTION_QUIET_MS / 1000}s of silence`);
  }
  if (config.peerUrl) {
    for (let probe = 0; probe < PROMOTION_PROBES; probe += 1) {
      if (probe > 0) await sleep(PROMOTION_PROBE_INTERVAL_MS);
      let peer = null;
      try {
        peer = await peerJson(`${config.peerUrl}/replica/manifest`);
      } catch {
        peer = null;
      }
      if (peer?.role === "primary" && (peer.status === "active" || peer.status === "activating_successor")) {
        throw new Error("the primary is still serving; promotion refused");
      }
    }
  }
  return promoteReplicaToPrimary();
}

export function buildReplicaManifest() {
  const current = getGovernanceState();
  const peer = getReplicaPeer();
  return {
    schema: REPLICA_MANIFEST_SCHEMA,
    status: current.status,
    role: current.replicaRole || null,
    epoch: current.epoch,
    imageDigest: current.imageDigest,
    lineageDigest: sha256Digest(canonicalStringify(current.lineage)),
    governanceKeyId: current.keyMaterial.governanceKeyId,
    activationKeyId: current.keyMaterial.activationKeyId,
    replicaSerial: current.replicaSerial || 0,
    peer: peer ? { instanceName: peer.instanceName || null, role: peer.role || null, recordedAt: peer.recordedAt || null } : null,
    health: getReplicaHealth(),
  };
}

export function watchGovernanceChanges() {
  if (unsubscribeStateChanges) return;
  unsubscribeStateChanges = onGovernanceStateChange((_state, { replicated }) => {
    if (!replicated) backgroundSyncDue = true;
  });
}

export function startReplicaSupervisor({ config = replicaConfig(), intervalMs = SUPERVISOR_INTERVAL_MS, onCustodyApplied = null } = {}) {
  if (supervisorTimer || !config.peerUrl) return;
  watchGovernanceChanges();
  const tick = async () => {
    try {
      await superviseOnce({ config, onCustodyApplied });
    } catch (error) {
      recordReplicaHealth({ lastError: error.message });
      console.error("[ReplicaCustody] supervisor tick failed:", error.message);
    }
  };
  supervisorTimer = setInterval(tick, intervalMs);
  tick();
}

export async function superviseOnce({ config = replicaConfig(), onCustodyApplied = null } = {}) {
  const current = getGovernanceState();
  if (current.status === "inactive" && current.lineage.length === 0) {
    const manifest = await pullCustodyFromPeer({ config });
    if (manifest && onCustodyApplied) await onCustodyApplied(manifest);
    return;
  }
  if (getReplicaRole() !== "primary") return;
  if (backgroundSyncDue && getReplicaPeer()) {
    backgroundSyncDue = false;
    try {
      await replicateGovernanceState();
    } catch (error) {
      backgroundSyncDue = true;
      throw error;
    }
  }
  await sendHeartbeatToPeer();
}

function syncUrlFor(address) {
  if (!address) return null;
  const host = String(address).replace(/^::ffff:/, "");
  return host.includes(":") ? `http://[${host}]:${CUSTODY_PORT}` : `http://${host}:${CUSTODY_PORT}`;
}

async function peerJson(url, { method = "GET", body = null } = {}) {
  const response = await fetchPeer(url, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(PEER_TIMEOUT_MS),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`${method} ${new URL(url).pathname} returned ${response.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text);
}

export function setReplicaCustodyDependenciesForTests({ attestationVerifier, tokenRequester, peerFetcher, sleeper, now } = {}) {
  if (attestationVerifier) verifyAttestation = attestationVerifier;
  if (tokenRequester) requestToken = tokenRequester;
  if (peerFetcher) fetchPeer = peerFetcher;
  if (sleeper) sleep = sleeper;
  if (now) custodyNow = now;
}

export function resetReplicaCustodyForTests() {
  verifyAttestation = verifyConfidentialSpaceAttestation;
  requestToken = requestAttestationToken;
  fetchPeer = (url, options) => fetch(url, options);
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  custodyNow = () => new Date();
  openChallenges.clear();
  backgroundSyncDue = false;
  if (supervisorTimer) clearInterval(supervisorTimer);
  supervisorTimer = null;
  if (unsubscribeStateChanges) unsubscribeStateChanges();
  unsubscribeStateChanges = null;
}

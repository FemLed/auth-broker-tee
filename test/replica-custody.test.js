import test from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { createInMemoryGovernanceKeyMaterial, signGovernancePayload } from "../src/governance-crypto.js";
import {
  getGovernanceState,
  initializeGovernance,
  issueTenantAdmissionCertificate,
  mayServePath,
  recordAcceptedRouteVersion,
  replicateGovernanceState,
  resetGovernanceForTests,
  setGovernanceStateReplicator,
  setReplicaRole,
} from "../src/governance-state.js";
import {
  buildKeyAttestation,
  buildReplicaManifest,
  issueCustodyChallenge,
  PROMOTION_QUIET_MS,
  promoteToPrimary,
  pullCustodyFromPeer,
  receiveHeartbeat,
  receiveSyncBundle,
  REPLICA_CUSTODY_AUDIENCE,
  replicateToCustodian,
  resetReplicaCustodyForTests,
  sendHeartbeatToPeer,
  serveCustodyRequest,
  setReplicaCustodyDependenciesForTests,
  superviseOnce,
  watchGovernanceChanges,
} from "../src/governance-replica-custody.js";
import {
  handleReplicaCustodyChallenge,
  handleReplicaCustodyRequest,
  handleReplicaPromote,
  resetGovernanceRouteSecurityForTests,
  setGovernanceOidcVerifierForTests,
} from "../src/governance-routes.js";

const SERVICE_ACCOUNT = "auth-broker-tee@prod-femled-couple-router.iam.gserviceaccount.com";
const A_INSTANCE = "auth-broker-tee-a-bc6e49d016f4";
const B_INSTANCE = "auth-broker-tee-b-bc6e49d016f4";
const A_ADDRESS = "10.138.0.11";
const B_ADDRESS = "10.138.0.12";
const TENANT = "019a8314-3e69-7bb1-b8ee-19bc54723979";
const OTHER_TENANT = "019a8314-3e69-7bb1-b8ee-19bc54723980";
const TENANT_ROUTE_PUBLIC_KEY_PEM = createInMemoryGovernanceKeyMaterial().governancePublicKeyPem;

// One process plays both replicas: each replica is its own governance state
// object, swapped in while that replica runs. Peer HTTP calls are routed to the
// target replica's custody functions with its state swapped in.
function createHarness(t) {
  const replicas = new Map();
  const traffic = [];
  let running = null;
  let clock = Date.parse("2026-10-14T12:00:00Z");

  const harness = {
    traffic,
    advance(ms) {
      clock += ms;
    },
    add(name, { instanceName, address, peer, genesis = false }) {
      resetGovernanceForTests(null);
      const state = genesis
        ? initializeGovernance({ mode: "genesis", now: new Date("2026-05-05T00:00:00Z") })
        : initializeGovernance();
      resetGovernanceForTests(null);
      const replica = {
        name,
        instanceName,
        address,
        url: `http://${address}:8080`,
        config: {
          bootRole: genesis ? "primary" : "custodian",
          peerUrl: `http://${peer.address}:8080`,
          peerInstance: peer.instanceName,
        },
        state,
        down: false,
        dropReplies: false,
      };
      replicas.set(name, replica);
      return replica;
    },
    async as(name, fn) {
      const previous = running;
      running = replicas.get(name);
      resetGovernanceForTests(running.state);
      try {
        return await fn(running);
      } finally {
        running = previous;
        resetGovernanceForTests(previous ? previous.state : null);
      }
    },
  };

  setGovernanceStateReplicator(replicateToCustodian);
  setReplicaCustodyDependenciesForTests({
    now: () => new Date(clock),
    sleeper: async () => {},
    tokenRequester: async (nonces, { audience }) => JSON.stringify({
      instance: running.instanceName,
      nonce: nonces[0],
      audience,
      imageDigest: getGovernanceState().imageDigest,
    }),
    attestationVerifier: async (token, { expectedNonce, expectedImageDigest, expectedAudience }) => {
      const claims = JSON.parse(token);
      if (claims.nonce !== expectedNonce) throw new Error("attestation nonce mismatch");
      if (claims.audience !== expectedAudience) throw new Error("attestation audience mismatch");
      if (claims.imageDigest !== expectedImageDigest) throw new Error("attestation image digest mismatch");
      return {
        submods: {
          gce: { project_id: "prod-femled-couple-router", project_number: "125139120897", instance_name: claims.instance },
          confidential_space: { support_attributes: ["LATEST", "STABLE", "USABLE"] },
          container: { image_digest: claims.imageDigest },
        },
        google_service_accounts: [SERVICE_ACCOUNT],
      };
    },
    peerFetcher: async (url, options = {}) => {
      const { origin, pathname } = new URL(url);
      const target = [...replicas.values()].find((replica) => replica.url === origin);
      if (!target || target.down) throw new Error(`connect ECONNREFUSED ${origin}`);
      const caller = running;
      const body = options.body ? JSON.parse(options.body) : null;
      let status = 200;
      let result;
      try {
        result = await harness.as(target.name, async () => {
          switch (pathname) {
            case "/replica/custody-challenge":
              return issueCustodyChallenge();
            case "/replica/custody-request":
              return serveCustodyRequest({ ...body, requesterAddress: caller.address }, { config: target.config });
            case "/replica/sync":
              return receiveSyncBundle(body);
            case "/replica/heartbeat":
              return receiveHeartbeat(body);
            case "/replica/manifest":
              return buildReplicaManifest();
            default:
              throw new Error(`no route ${pathname}`);
          }
        });
      } catch (error) {
        status = 409;
        result = { error: error.message };
      }
      if (harness.tamper && status === 200) result = await harness.tamper(pathname, result);
      const text = JSON.stringify(result);
      traffic.push({ pathname, request: options.body || "", response: text });
      if (target.dropReplies) throw new Error("socket hang up");
      return { ok: status < 300, status, text: async () => text };
    },
  });

  t.after(() => {
    resetReplicaCustodyForTests();
    setGovernanceStateReplicator(null);
    resetGovernanceForTests(null);
  });
  return harness;
}

function addPrimaryAndCustodian(harness) {
  const a = harness.add("a", { instanceName: A_INSTANCE, address: A_ADDRESS, genesis: true, peer: { instanceName: B_INSTANCE, address: B_ADDRESS } });
  const b = harness.add("b", { instanceName: B_INSTANCE, address: B_ADDRESS, peer: { instanceName: A_INSTANCE, address: A_ADDRESS } });
  a.state.replicaRole = "primary";
  b.state.replicaRole = "custodian";
  return { a, b };
}

async function enrolledPair(harness) {
  const pair = addPrimaryAndCustodian(harness);
  await harness.as("b", () => pullCustodyFromPeer({ config: pair.b.config }));
  return pair;
}

function tenantAdmissionFields(tenant = TENANT) {
  return {
    tenant,
    tenantRouteSigningKeys: [{ keyId: `route-key-${tenant.slice(-4)}`, alg: "Ed25519", publicKeyPem: TENANT_ROUTE_PUBLIC_KEY_PEM }],
    minRouteVersion: 2,
    allowedApiHosts: [`api-${tenant}.femled.ai`],
    allowedAppHosts: [`app-${tenant}.femled.ai`],
    allowedBrokerAudiences: ["https://oauth-tee.femled.ai"],
  };
}

function admittedTenants(replica) {
  return replica.state.transferredState.routePolicy.admittedTenants;
}

test("a fresh replica pulls custody from the primary and becomes its custodian", async (t) => {
  const harness = createHarness(t);
  const { a, b } = addPrimaryAndCustodian(harness);
  const ownActivationKeyId = b.state.keyMaterial.activationKeyId;

  const manifest = await harness.as("b", () => pullCustodyFromPeer({ config: b.config }));

  assert.equal(manifest.status, "active");
  assert.equal(b.state.status, "active");
  assert.equal(b.state.epoch, a.state.epoch);
  assert.equal(b.state.replicaRole, "custodian");
  assert.equal(b.state.keyMaterial.governanceKeyId, a.state.keyMaterial.governanceKeyId);
  assert.equal(b.state.keyMaterial.activationKeyId, ownActivationKeyId);
  assert.deepEqual(b.state.lineage, a.state.lineage);
  assert.equal(b.state.replicaPeer.instanceName, A_INSTANCE);
  assert.equal(b.state.replicaPeer.role, "primary");
  assert.equal(a.state.replicaPeer.instanceName, B_INSTANCE);
  assert.equal(a.state.replicaPeer.role, "custodian");
  assert.equal(a.state.replicaPeer.syncUrl, `http://${B_ADDRESS}:8080`);
  for (const exchange of harness.traffic) {
    assert.doesNotMatch(exchange.request + exchange.response, /PRIVATE KEY/);
  }
});

test("custody goes only to the configured peer instance", async (t) => {
  const harness = createHarness(t);
  harness.add("a", { instanceName: A_INSTANCE, address: A_ADDRESS, genesis: true, peer: { instanceName: B_INSTANCE, address: B_ADDRESS } });
  const c = harness.add("c", { instanceName: "auth-broker-tee-c-bc6e49d016f4", address: "10.138.0.13", peer: { instanceName: A_INSTANCE, address: A_ADDRESS } });

  await assert.rejects(
    harness.as("c", () => pullCustodyFromPeer({ config: c.config })),
    /not the configured peer/,
  );
  assert.equal(c.state.status, "inactive");
  assert.equal(c.state.lineage.length, 0);
});

test("a replica with no configured peer re-keys nobody", async (t) => {
  const harness = createHarness(t);
  const { a, b } = addPrimaryAndCustodian(harness);
  a.config.peerInstance = null;

  await assert.rejects(
    harness.as("b", () => pullCustodyFromPeer({ config: b.config })),
    /no configured peer/,
  );
  assert.equal(b.state.status, "inactive");
  assert.equal(a.state.replicaPeer, null);
});

test("custody is refused to a replica of a different image", async (t) => {
  const harness = createHarness(t);
  const { b } = addPrimaryAndCustodian(harness);
  b.state.imageDigest = `sha256:${"1".repeat(64)}`;

  await assert.rejects(
    harness.as("b", () => pullCustodyFromPeer({ config: b.config })),
    /different image/,
  );
  assert.equal(b.state.status, "inactive");
});

test("custody requires an attestation bound to the requester's own keys and a fresh challenge", async (t) => {
  const harness = createHarness(t);
  const { a } = addPrimaryAndCustodian(harness);
  const attacker = createInMemoryGovernanceKeyMaterial();

  const { challenge } = await harness.as("a", () => issueCustodyChallenge());
  const evidence = await harness.as("b", () => buildKeyAttestation({ purpose: "custody-request", challenge }));
  assert.equal(JSON.parse(evidence.attestationToken).audience, REPLICA_CUSTODY_AUDIENCE);
  const forged = { ...evidence, activationPublicKeyPem: attacker.activationPublicKeyPem };
  await assert.rejects(
    harness.as("a", () => serveCustodyRequest({ challenge, evidence: forged, requesterAddress: B_ADDRESS }, { config: a.config })),
    /nonce mismatch/,
  );
  // The challenge was consumed by the failed attempt.
  await assert.rejects(
    harness.as("a", () => serveCustodyRequest({ challenge, evidence, requesterAddress: B_ADDRESS }, { config: a.config })),
    /unknown or expired custody challenge/,
  );
  const unchallenged = await harness.as("b", () => buildKeyAttestation({ purpose: "custody-request", challenge: "never-issued" }));
  await assert.rejects(
    harness.as("a", () => serveCustodyRequest({ challenge: "never-issued", evidence: unchallenged, requesterAddress: B_ADDRESS }, { config: a.config })),
    /unknown or expired custody challenge/,
  );
  assert.equal(a.state.replicaPeer, null);
});

test("a custody bundle is applied only with the sender's own attestation", async (t) => {
  const harness = createHarness(t);
  const { b } = addPrimaryAndCustodian(harness);
  const c = harness.add("c", { instanceName: "auth-broker-tee-c-bc6e49d016f4", address: "10.138.0.13", peer: { instanceName: A_INSTANCE, address: A_ADDRESS } });

  harness.tamper = (pathname, result) => (pathname === "/replica/custody-request" ? { ...result, senderAttestation: undefined } : result);
  await assert.rejects(harness.as("b", () => pullCustodyFromPeer({ config: b.config })), /does not answer this custody-send challenge/);

  // A genuine attestation, but from another broker instance, over the bundle.
  harness.tamper = (pathname, result) => {
    if (pathname !== "/replica/custody-request") return result;
    const elsewhere = { ...result };
    return harness.as("c", async () => ({
      ...elsewhere,
      senderAttestation: await buildKeyAttestation({ purpose: "custody-send", challenge: result.bundle.payloadDigest }),
    }));
  };
  await assert.rejects(harness.as("b", () => pullCustodyFromPeer({ config: b.config })), /not the configured peer/);
  assert.equal(b.state.status, "inactive");
  assert.equal(c.state.status, "inactive");
});

test("custody is applied only by a fresh inactive replica", async (t) => {
  const harness = createHarness(t);
  const { b } = await enrolledPair(harness);

  assert.equal(await harness.as("b", () => pullCustodyFromPeer({ config: b.config })), null);
  assert.equal(b.state.status, "active");
});

test("every released change has been acknowledged by the custodian", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);

  await harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields()));

  assert.equal(b.state.replicaSerial, a.state.replicaSerial);
  assert.deepEqual(admittedTenants(b), admittedTenants(a));
  assert.ok(admittedTenants(b)[TENANT]);
  const syncBundle = JSON.parse(harness.traffic.findLast((exchange) => exchange.pathname === "/replica/sync").request).bundle;
  assert.doesNotMatch(JSON.stringify(syncBundle), /PRIVATE KEY|routePolicy/);

  await assert.rejects(harness.as("b", () => receiveSyncBundle({ bundle: syncBundle })), /not newer/);
  const foreign = await signGovernancePayload(syncBundle.payload, createInMemoryGovernanceKeyMaterial());
  await assert.rejects(harness.as("b", () => receiveSyncBundle({ bundle: foreign })));
  await assert.rejects(harness.as("a", () => receiveSyncBundle({ bundle: syncBundle })), /only a custodian/);
});

test("a change the custodian does not acknowledge is reverted and never released", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);
  b.down = true;

  await assert.rejects(
    harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields())),
    /not acknowledged by the custodian/,
  );
  assert.equal(admittedTenants(a)[TENANT], undefined);
  assert.equal(a.state.replicaHealth.lastError.includes("ECONNREFUSED"), true);

  b.down = false;
  await harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields()));
  assert.ok(admittedTenants(a)[TENANT]);
  assert.deepEqual(admittedTenants(b), admittedTenants(a));
});

test("a lost acknowledgement does not wedge the custodian", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);
  b.dropReplies = true;

  await assert.rejects(
    harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields())),
    /not acknowledged/,
  );
  // The custodian applied the change, the primary reverted it.
  assert.ok(admittedTenants(b)[TENANT]);
  assert.equal(admittedTenants(a)[TENANT], undefined);

  b.dropReplies = false;
  await harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields(OTHER_TENANT)));
  assert.equal(b.state.replicaSerial, a.state.replicaSerial);
  assert.deepEqual(admittedTenants(b), admittedTenants(a));
  assert.equal(admittedTenants(b)[TENANT], undefined);
});

test("bookkeeping changed outside a commit reaches the custodian in the background", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);
  await harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields()));
  watchGovernanceChanges();

  await harness.as("a", () => recordAcceptedRouteVersion({ tenant: TENANT, routeVersion: 7, routeDigest: `sha256:${"7".repeat(64)}` }));
  assert.equal(admittedTenants(b)[TENANT].latestAcceptedRouteVersion || 0, 0);
  await harness.as("a", () => superviseOnce({ config: a.config }));

  assert.equal(admittedTenants(b)[TENANT].latestAcceptedRouteVersion, 7);
  assert.equal(b.state.replicaSerial, a.state.replicaSerial);
});

test("a retired custodian re-keys nobody", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);
  a.state.status = "retired";
  await harness.as("a", () => replicateGovernanceState());
  assert.equal(b.state.status, "retired");

  const restarted = harness.add("a", { instanceName: A_INSTANCE, address: A_ADDRESS, peer: { instanceName: B_INSTANCE, address: B_ADDRESS } });
  restarted.config.bootRole = "primary";
  await assert.rejects(
    harness.as("a", () => pullCustodyFromPeer({ config: restarted.config })),
    /does not hold the lineage key/,
  );
  assert.equal(restarted.state.status, "inactive");
});

test("a restarted primary is re-keyed by its custodian and comes back as primary", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);
  await harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields()));

  const restarted = harness.add("a", { instanceName: A_INSTANCE, address: A_ADDRESS, peer: { instanceName: B_INSTANCE, address: B_ADDRESS } });
  restarted.config.bootRole = "primary";
  const manifest = await harness.as("a", () => pullCustodyFromPeer({ config: restarted.config }));

  assert.equal(manifest.status, "active");
  assert.equal(restarted.state.replicaRole, "primary");
  assert.equal(restarted.state.keyMaterial.governanceKeyId, a.state.keyMaterial.governanceKeyId);
  assert.notEqual(restarted.state.keyMaterial.activationKeyId, a.state.keyMaterial.activationKeyId);
  assert.deepEqual(restarted.state.lineage, a.state.lineage);
  assert.deepEqual(admittedTenants(restarted), admittedTenants(a));
  assert.equal(restarted.state.replicaPeer.syncUrl, `http://${B_ADDRESS}:8080`);
  assert.equal(b.state.replicaPeer.role, "primary");

  // The restarted primary's commits reach the same custodian.
  await harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields(OTHER_TENANT)));
  assert.ok(admittedTenants(b)[OTHER_TENANT]);
});

test("heartbeats keep the custodian from being promoted while the primary lives", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);

  const reply = await harness.as("a", () => sendHeartbeatToPeer());
  assert.equal(reply.replicaSerial, a.state.replicaSerial);
  harness.advance(PROMOTION_QUIET_MS - 1000);
  a.down = true;
  await assert.rejects(harness.as("b", () => promoteToPrimary({ config: b.config })), /promotion is allowed after/);
  assert.equal(b.state.replicaRole, "custodian");
});

test("promotion needs a custodian, a silent primary, and no primary answering", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);
  harness.advance(PROMOTION_QUIET_MS + 1000);

  await assert.rejects(harness.as("a", () => promoteToPrimary({ config: a.config })), /only a custodian/);
  await assert.rejects(harness.as("b", () => promoteToPrimary({ config: b.config })), /still serving/);

  a.down = true;
  const manifest = await harness.as("b", () => promoteToPrimary({ config: b.config }));
  assert.equal(manifest.status, "active");
  assert.equal(b.state.replicaRole, "primary");
  assert.equal(b.state.replicaPeer, null);
  assert.equal(await harness.as("b", () => mayServePath("/login")), true);
});

test("an old primary that survives a promotion can commit nothing", async (t) => {
  const harness = createHarness(t);
  const { a, b } = await enrolledPair(harness);
  harness.advance(PROMOTION_QUIET_MS + 1000);
  a.down = true;
  await harness.as("b", () => promoteToPrimary({ config: b.config }));
  a.down = false;

  await assert.rejects(
    harness.as("a", () => issueTenantAdmissionCertificate(tenantAdmissionFields())),
    /only a custodian accepts/,
  );
  assert.equal(admittedTenants(a)[TENANT], undefined);
  assert.equal(admittedTenants(b)[TENANT], undefined);

  // The promoted replica commits on its own until a new custodian enrolls.
  await harness.as("b", () => issueTenantAdmissionCertificate(tenantAdmissionFields()));
  assert.ok(admittedTenants(b)[TENANT]);
});

test("a custodian serves no public routes until promoted", async (t) => {
  const harness = createHarness(t);
  await enrolledPair(harness);

  await harness.as("b", () => {
    assert.equal(mayServePath("/login"), false);
    assert.equal(mayServePath("/governance/tenant-admission"), false);
    assert.equal(mayServePath("/health"), true);
    assert.equal(mayServePath("/.well-known/femled-tee-governance.json"), true);
  });
});

test("replica custody endpoints refuse public callers and promotion requires the failover workflow", async (t) => {
  const harness = createHarness(t);
  addPrimaryAndCustodian(harness);
  resetGovernanceRouteSecurityForTests();
  t.after(() => resetGovernanceRouteSecurityForTests());

  await harness.as("a", async () => {
    const publicChallenge = createMockResponse();
    await handleReplicaCustodyChallenge(replicaRequest({ method: "GET", remoteAddress: "198.51.100.40" }), publicChallenge);
    assert.equal(publicChallenge.statusCode, 403);

    const privateChallenge = createMockResponse();
    await handleReplicaCustodyChallenge(replicaRequest({ method: "GET", remoteAddress: `::ffff:${B_ADDRESS}` }), privateChallenge);
    assert.equal(privateChallenge.statusCode, 200);

    const publicRequest = createMockResponse();
    await handleReplicaCustodyRequest(replicaRequest({ body: {}, remoteAddress: "198.51.100.41" }), publicRequest);
    assert.equal(publicRequest.statusCode, 403);
  });

  const seen = [];
  setGovernanceOidcVerifierForTests(async (authHeader, expected) => {
    seen.push(expected);
    if (authHeader !== "Bearer failover-workflow") throw new Error("invalid test OIDC token");
    return { event_name: "workflow_dispatch", job_workflow_ref: expected.workflowRefs[0] };
  });
  await harness.as("b", async () => {
    const unauthenticated = createMockResponse();
    await handleReplicaPromote(replicaRequest({ body: {}, remoteAddress: "198.51.100.42" }), unauthenticated);
    assert.equal(unauthenticated.statusCode, 401);
    assert.equal(getGovernanceState().replicaRole, "custodian");
  });
  assert.deepEqual(seen.at(-1).workflowRefs, ["FemLed/auth-broker-tee/.github/workflows/replica-failover.yml@refs/heads/master"]);
  assert.deepEqual([...seen.at(-1).allowedEvents], ["workflow_dispatch"]);
});

test("setReplicaRole accepts only the two replica roles", () => {
  resetGovernanceForTests(null);
  initializeGovernance();
  assert.throws(() => setReplicaRole("leader"), /unknown replica role/);
  setReplicaRole("custodian");
  assert.equal(getGovernanceState().replicaRole, "custodian");
  resetGovernanceForTests(null);
});

function replicaRequest({ method = "POST", body = null, authorization = null, remoteAddress }) {
  const req = Readable.from(body === null ? [] : [JSON.stringify(body)]);
  req.method = method;
  req.headers = authorization ? { authorization } : {};
  req.socket = { remoteAddress };
  return req;
}

function createMockResponse() {
  return {
    statusCode: 0,
    headers: {},
    body: "",
    writeHead(status, headers = {}) {
      this.statusCode = status;
      this.headers = headers;
    },
    end(chunk = "") {
      this.body += chunk;
    },
  };
}

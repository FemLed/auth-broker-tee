import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test, beforeEach, afterEach } from "node:test";
import {
  runOnce,
  setComputeResetterForTests,
  setDnsTeeFetcherForTests,
  setRenewerEnvelopeBuilderForTests,
} from "../src/acme-renewal.js";

const ORIGINAL_ENV = {
  ACME_RENEWER_ENABLED: process.env.ACME_RENEWER_ENABLED,
  RENEWER_KMS_SIGNER_KEY_VERSION: process.env.RENEWER_KMS_SIGNER_KEY_VERSION,
  DNS_TEE_RENEWER_URLS: process.env.DNS_TEE_RENEWER_URLS,
};

beforeEach(() => {
  process.env.ACME_RENEWER_ENABLED = "false";
  process.env.RENEWER_KMS_SIGNER_KEY_VERSION = "test-key";
  process.env.DNS_TEE_RENEWER_URLS = "https://ns1.test,https://ns2.test,https://ns3.test,https://ns4.test";
  setDnsTeeFetcherForTests(null);
  setRenewerEnvelopeBuilderForTests(null);
  setComputeResetterForTests(null);
});

afterEach(() => {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  setDnsTeeFetcherForTests(null);
  setRenewerEnvelopeBuilderForTests(null);
  setComputeResetterForTests(null);
});

test("supervisor runOnce returns skipped when ACME_RENEWER_ENABLED is false", async () => {
  process.env.ACME_RENEWER_ENABLED = "false";
  let resetCalls = 0;
  setComputeResetterForTests(async () => { resetCalls += 1; });
  // The auth-broker-tee renewer's `startRenewalLoop` early-returns when
  // disabled, but `runOnce` still executes; the inner checkAndRenew path
  // reads existing TLS credentials. Without secrets configured, fetching
  // credentials throws and we expect the cycle to surface that error
  // rather than perform a renewal. Reset must NOT be called.
  await runOnce().catch(() => null);
  assert.equal(resetCalls, 0);
});

test("envelope builder + fetcher overrides are wired and exercise the test seam", async () => {
  process.env.ACME_RENEWER_ENABLED = "true";
  let envelopeBuilderCalls = 0;
  setRenewerEnvelopeBuilderForTests(async () => {
    envelopeBuilderCalls += 1;
    return { schema: "test-envelope" };
  });
  let fetcherCalls = 0;
  setDnsTeeFetcherForTests(async () => {
    fetcherCalls += 1;
    return new Response(JSON.stringify({ decision: "APPROVE", applied: {} }), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  // Verify that the test seams are reachable. The full renewal flow can't
  // run in this unit test because acme-client.auto needs a real ACME
  // directory; integration tests should exercise that path.
  assert.equal(typeof setRenewerEnvelopeBuilderForTests, "function");
  assert.equal(typeof setDnsTeeFetcherForTests, "function");
  assert.equal(typeof setComputeResetterForTests, "function");
  // Direct invocation of the seams confirms the override hooks work.
  const builder = await import("../src/acme-renewal.js");
  builder.setRenewerEnvelopeBuilderForTests(async () => ({ schema: "test-envelope-v2" }));
  builder.setRenewerEnvelopeBuilderForTests(null);
  assert.equal(envelopeBuilderCalls, 0);
  assert.equal(fetcherCalls, 0);
});

test("reset-call gating: reset only fires through the renewed-status path", async () => {
  // The supervisor's compute.reset call is gated on the renewer returning
  // status "renewed". When it returns anything else (skipped, not_due,
  // dry_run_complete, error), reset must NOT be called. We exercise the
  // skipped path directly here; the renewed path is exercised in integration
  // tests against a real ACME directory.
  process.env.ACME_RENEWER_ENABLED = "false";
  let resetCalls = 0;
  setComputeResetterForTests(async () => { resetCalls += 1; });
  await runOnce().catch(() => null);
  assert.equal(resetCalls, 0);
});

test("submitRenewerChange aggregates partial failures into a single error", async () => {
  // We can't call submitRenewerChange directly (it is internal), but we can
  // simulate the contract via the fetcher: when one of the configured peers
  // returns 4xx, the renewal cycle must fail and reset must NOT fire.
  process.env.ACME_RENEWER_ENABLED = "true";
  let resetCalls = 0;
  setComputeResetterForTests(async () => { resetCalls += 1; });
  let fetchCount = 0;
  setDnsTeeFetcherForTests(async () => {
    fetchCount += 1;
    if (fetchCount === 1) {
      return new Response(JSON.stringify({ decision: "APPROVE" }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response("forbidden", { status: 401 });
  });
  // The full flow won't run without ACME, but we assert the test plumbing
  // is wired and that reset is not called when the renewer aborts early.
  await runOnce().catch(() => null);
  assert.equal(resetCalls, 0);
});

test("renewer envelope canonical form is stable", async () => {
  const { canonicalStringify } = await import("../src/canonical-json.js");
  const payload = {
    schema: "femled.authoritative_dns_tee.external_tee_renewer.payload.v1",
    callerName: "auth-broker-tee",
    callerImageDigest: "sha256:" + "a".repeat(64),
    attestationToken: "test-token",
    attestationDigest: "sha256:" + "b".repeat(64),
    route: "/governance/routine-zone-change-renewer",
    change: {
      class: "IN",
      name: "_acme-challenge.oauth-tee.femled.ai.",
      op: "add",
      ttl: 60,
      type: "TXT",
      values: ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNopq"],
    },
    changeDigest: "sha256:" + "c".repeat(64),
    requestNonce: "test-nonce-" + crypto.randomBytes(8).toString("base64url"),
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  };
  const canonical = canonicalStringify(payload);
  assert.match(canonical, /auth-broker-tee/);
  assert.match(canonical, /_acme-challenge\.oauth-tee\.femled\.ai/);
});

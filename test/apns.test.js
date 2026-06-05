import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";
import { buildAlertPushBody } from "../src/apns.js";
import { handlePushSendAlert } from "../src/routes.js";

test("buildAlertPushBody preserves coach haptic custom data beside broker aps", () => {
  const body = JSON.parse(buildAlertPushBody({
    alert: {
      title: "Immediate Compliance Required",
      body: "Non-compliance is escalating. Return to compliant state.",
    },
    sound: "default",
    badge: 2,
    interruptionLevel: "time-sensitive",
    threadId: "haptic-compliance",
    customData: {
      tier: 2,
      episodeId: "episode-123",
      shouldVibrate: true,
      pattern: "training",
      timestamp: "2026-05-03T19:00:00.000Z",
    },
  }));

  assert.deepEqual(body.aps, {
    alert: {
      title: "Immediate Compliance Required",
      body: "Non-compliance is escalating. Return to compliant state.",
    },
    sound: "default",
    badge: 2,
    "interruption-level": "time-sensitive",
    "thread-id": "haptic-compliance",
  });
  assert.equal(body.tier, 2);
  assert.equal(body.episodeId, "episode-123");
  assert.equal(body.shouldVibrate, true);
  assert.equal(body.pattern, "training");
});

test("buildAlertPushBody preserves digital leash custom data beside broker aps", () => {
  const body = JSON.parse(buildAlertPushBody({
    alert: {
      title: "Digital Leash Tightened",
      body: "example.com has been added to your blocklist",
    },
    sound: "default",
    badge: 0,
    interruptionLevel: "active",
    threadId: "digital-leash",
    customData: {
      digitalLeashAction: "domain_added",
      domain: "example.com",
      cycleCount: 0,
      timestamp: "2026-05-03T19:00:00.000Z",
    },
  }));

  assert.deepEqual(body.aps, {
    alert: {
      title: "Digital Leash Tightened",
      body: "example.com has been added to your blocklist",
    },
    sound: "default",
    badge: 0,
    "interruption-level": "active",
    "thread-id": "digital-leash",
  });
  assert.equal(body.digitalLeashAction, "domain_added");
  assert.equal(body.domain, "example.com");
  assert.equal(body.cycleCount, 0);
});

test("buildAlertPushBody rejects caller-controlled aps custom data", () => {
  assert.throws(
    () => buildAlertPushBody({
      alert: { title: "Compliance Check", body: "AURA protocol violation detected" },
      interruptionLevel: "time-sensitive",
      customData: {
        aps: { "interruption-level": "critical" },
      },
    }),
    /customData\.aps is not allowed/
  );
});

test("handlePushSendAlert rejects customData.aps before token resolution", async () => {
  process.env.BROKER_API_KEY = "test-broker-key";

  const req = Readable.from([JSON.stringify({
    coupleId: "11111111-1111-4111-8111-111111111111",
    intentId: "intent-123",
    deviceTokens: ["a".repeat(64)],
    bundleId: "com.FemLed.FemLedCoach",
    apnsEnvironment: "production",
    alert: { title: "Compliance Check", body: "AURA protocol violation detected" },
    interruptionLevel: "time-sensitive",
    customData: {
      aps: { "interruption-level": "critical" },
    },
  })]);
  req.method = "POST";
  req.headers = { "x-broker-api-key": "test-broker-key" };

  const res = createMockResponse();
  await handlePushSendAlert(req, res);

  assert.equal(res.statusCode, 400);
  assert.deepEqual(JSON.parse(res.body), { error: "customData.aps is not allowed" });
});

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

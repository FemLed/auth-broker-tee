import assert from "node:assert/strict";
import test from "node:test";
import { GoogleAuth } from "google-auth-library";
import { FIRST_PRINCIPLES_MODEL } from "../src/first-principles-review.js";
import { buildVertexClient, REVIEW_REQUEST_TIMEOUT_MS } from "../src/vertex-gemini.js";

const UNDICI_GLOBAL_DISPATCHER = Symbol.for("undici.globalDispatcher.1");
const REVIEW_URL = `https://aiplatform.googleapis.com/v1beta1/projects/test-project/locations/global/publishers/google/models/${FIRST_PRINCIPLES_MODEL}:generateContent`;

async function sendReviewRequest() {
  // Node sets its dispatcher up lazily; there has to be one to put back.
  new Headers();
  const real = {
    fetch: globalThis.fetch,
    setTimeout: globalThis.setTimeout,
    dispatcher: globalThis[UNDICI_GLOBAL_DISPATCHER],
    getRequestHeaders: GoogleAuth.prototype.getRequestHeaders,
  };
  const sent = { requests: [], timers: [], dispatched: [] };
  globalThis.fetch = async (url, init) => {
    sent.requests.push({ url: String(url), init, dispatcher: globalThis[UNDICI_GLOBAL_DISPATCHER] });
    const answer = { candidates: [{ content: { role: "model", parts: [{ text: "{}" }] }, finishReason: "STOP" }] };
    return new Response(JSON.stringify(answer), { status: 200, headers: { "content-type": "application/json" } });
  };
  globalThis.setTimeout = (callback, delay, ...args) => {
    if (delay !== REVIEW_REQUEST_TIMEOUT_MS) return real.setTimeout(callback, delay, ...args);
    sent.timers.push(callback);
    return {};
  };
  globalThis[UNDICI_GLOBAL_DISPATCHER] = {
    dispatch(options, handler) {
      sent.dispatched.push({ options, handler });
      return true;
    },
  };
  GoogleAuth.prototype.getRequestHeaders = async () => new Headers({ Authorization: "Bearer machine-default-token" });
  try {
    const client = buildVertexClient({ accessToken: "test-token", project: "test-project" });
    await client.models.generateContent({ model: FIRST_PRINCIPLES_MODEL, contents: "a review context" });
  } finally {
    globalThis.fetch = real.fetch;
    globalThis.setTimeout = real.setTimeout;
    globalThis[UNDICI_GLOBAL_DISPATCHER] = real.dispatcher;
    GoogleAuth.prototype.getRequestHeaders = real.getRequestHeaders;
  }
  return sent;
}

// First in this file on purpose: nothing has used fetch yet, so on a Node that
// sets its dispatcher up lazily there is none to wrap until the client is built.
test("building the client sets Node's dispatcher up when nothing has used fetch yet", () => {
  buildVertexClient({ accessToken: "test-token", project: "test-project" });
  assert.equal(typeof globalThis[UNDICI_GLOBAL_DISPATCHER].dispatch, "function");
});

test("a review request goes to Vertex under the token it was given, bounded by its own 15-minute timeout", async () => {
  const { requests, timers } = await sendReviewRequest();
  assert.equal(requests.length, 1);
  const [{ url, init }] = requests;
  assert.equal(url, REVIEW_URL);
  assert.equal(init.method, "POST");
  assert.equal(init.headers.get("authorization"), "Bearer test-token");

  assert.equal(REVIEW_REQUEST_TIMEOUT_MS, 15 * 60 * 1000);
  // The SDK tells Vertex the deadline, in seconds, and arms one timer of that
  // length; when it fires, the request is aborted.
  assert.equal(init.headers.get("x-server-timeout"), "900");
  assert.ok(init.signal instanceof AbortSignal);
  assert.equal(timers.length, 1);
  assert.equal(init.signal.aborted, false);
  timers[0]();
  assert.equal(init.signal.aborted, true);
});

test("a review request leaves through a dispatcher without Undici's 300-second header and body timeouts", async () => {
  const { requests: [{ init, dispatcher }], dispatched } = await sendReviewRequest();
  assert.equal("dispatcher" in init, false);
  assert.equal(dispatched.length, 0);

  const { origin, pathname } = new URL(REVIEW_URL);
  const handler = {};
  const review = { origin, path: pathname, method: "POST", headersTimeout: 300_000, bodyTimeout: 300_000 };
  assert.equal(dispatcher.dispatch(review, handler), true);
  assert.deepEqual(dispatched[0].options, { origin, path: pathname, method: "POST", headersTimeout: 0, bodyTimeout: 0 });
  assert.equal(dispatched[0].handler, handler);

  for (const other of [
    { origin: "https://sts.googleapis.com", path: "/v1/token", method: "POST" },
    { origin, path: "/v1beta1/publishers/google/models?pageSize=300", method: "GET" },
    { origin, path: pathname.replace(":generateContent", ":streamGenerateContent"), method: "POST" },
    { origin: "https://example.com", path: pathname, method: "POST" },
  ]) {
    assert.equal(dispatcher.dispatch(other, handler), true);
    assert.equal(dispatched.at(-1).options, other);
    assert.deepEqual(Object.keys(other), ["origin", "path", "method"]);
  }
});

test("Node's own fetch takes a review request, and no other, to the dispatcher with both timeouts off", async () => {
  new Headers();
  const realDispatcher = globalThis[UNDICI_GLOBAL_DISPATCHER];
  const dispatched = [];
  globalThis[UNDICI_GLOBAL_DISPATCHER] = {
    dispatch(options) {
      dispatched.push(options);
      throw new Error("no network in this test");
    },
  };
  try {
    buildVertexClient({ accessToken: "test-token", project: "test-project" });
    const installed = globalThis[UNDICI_GLOBAL_DISPATCHER];
    buildVertexClient({ accessToken: "test-token", project: "test-project" });
    assert.equal(globalThis[UNDICI_GLOBAL_DISPATCHER], installed, "the wrapper is installed once");
    await assert.rejects(fetch(REVIEW_URL, { method: "POST", body: "{}" }), /fetch failed/);
    await assert.rejects(fetch("https://sts.googleapis.com/v1/token", { method: "POST", body: "{}" }), /fetch failed/);
  } finally {
    globalThis[UNDICI_GLOBAL_DISPATCHER] = realDispatcher;
  }
  assert.equal(dispatched.length, 2);
  const [review, other] = dispatched;
  assert.equal(`${review.origin}${review.path}`, REVIEW_URL);
  assert.equal(review.headersTimeout, 0);
  assert.equal(review.bodyTimeout, 0);
  assert.equal(`${other.origin}${other.path}`, "https://sts.googleapis.com/v1/token");
  assert.equal("headersTimeout" in other, false);
  assert.equal("bodyTimeout" in other, false);
});

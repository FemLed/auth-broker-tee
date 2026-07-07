import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRequestUrl } from "../src/http-helpers.js";

function fakeReq(url, host) {
  return { url, headers: host === undefined ? {} : { host } };
}

test("parseRequestUrl parses a normal request", () => {
  const url = parseRequestUrl(fakeReq("/health?probe=1", "oauth-tee.femled.ai"));
  assert.equal(url.pathname, "/health");
  assert.equal(url.searchParams.get("probe"), "1");
});

// Regression: the 2026-07-07 crash loop. Internet scanners send Host headers
// that are legal HTTP header values but invalid URL authorities; `new URL`
// throws on them, and inside the async request handler that throw became an
// unhandled rejection that killed the process (each crash-reboot re-minted
// TLS and burned a Let's Encrypt issuance). parseRequestUrl must swallow the
// parse failure and return null so the handler can answer 400 instead.
test("parseRequestUrl returns null (does not throw) on scanner-style Host headers", () => {
  const hostileHosts = [
    "a b",
    'evil.com"><script>',
    "[not-an-ipv6",
    "%%%",
  ];
  for (const host of hostileHosts) {
    assert.equal(parseRequestUrl(fakeReq("/health", host)), null, `Host ${JSON.stringify(host)} must yield null`);
  }
});

test("parseRequestUrl tolerates a missing Host header (HTTP/1.0)", () => {
  const url = parseRequestUrl(fakeReq("/login", undefined));
  assert.ok(url instanceof URL);
  assert.equal(url.pathname, "/login");
});

test("a rejected parse inside an async handler resolves instead of rejecting", async () => {
  const handler = async (req) => {
    const url = parseRequestUrl(req);
    if (!url) return { status: 400 };
    return { status: 200 };
  };
  await assert.doesNotReject(async () => {
    const result = await handler(fakeReq("/health", "a b"));
    assert.equal(result.status, 400);
  });
});

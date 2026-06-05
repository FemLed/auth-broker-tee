import assert from "node:assert/strict";
import test from "node:test";
import { buildPostAuthRedirect, extractDepositAuthCode } from "../src/routes.js";

test("web post-auth redirect carries auth_code without id_token", () => {
  const redirect = buildPostAuthRedirect({
    tenant: "019a8314-3e69-7bb1-b8ee-19bc54723979",
    authCode: "opaque-code.with-special_chars",
    returnTo: null,
  });
  const url = new URL(redirect);

  assert.equal(url.origin, "https://app-019a8314-3e69-7bb1-b8ee-19bc54723979.femled.ai");
  assert.equal(url.pathname, "/chat");
  assert.equal(url.searchParams.get("auth_success"), "true");
  assert.equal(url.searchParams.get("auth_code"), "opaque-code.with-special_chars");
  assert.equal(url.searchParams.has("id_token"), false);
});

test("native post-auth redirect carries auth_code without id_token", () => {
  const redirect = buildPostAuthRedirect({
    tenant: "019a8314-3e69-7bb1-b8ee-19bc54723979",
    authCode: "opaque-native-code",
    returnTo: "femled-coach://oauth",
  });
  const url = new URL(redirect);

  assert.equal(url.protocol, "femled-coach:");
  assert.equal(url.host, "oauth");
  assert.equal(url.searchParams.get("auth_success"), "true");
  assert.equal(url.searchParams.get("tenant"), "019a8314-3e69-7bb1-b8ee-19bc54723979");
  assert.equal(url.searchParams.get("auth_code"), "opaque-native-code");
  assert.equal(url.searchParams.has("id_token"), false);
});

test("deposit response must include a non-empty auth_code", () => {
  assert.equal(extractDepositAuthCode({ auth_code: "opaque-code" }), "opaque-code");
  assert.equal(extractDepositAuthCode({}), null);
  assert.equal(extractDepositAuthCode({ auth_code: "" }), null);
  assert.equal(extractDepositAuthCode({ auth_code: 123 }), null);
});

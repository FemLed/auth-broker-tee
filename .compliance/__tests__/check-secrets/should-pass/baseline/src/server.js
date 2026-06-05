// Baseline: SECRETS object exactly mirrors the allowlist's read map.
const SECRETS = {
  FOO_TOKEN: "foo-token-secret",
};

function init() {
  return process.env.FOO_TOKEN;
}

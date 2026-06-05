const SECRETS = {
  FOO_TOKEN: "foo-token-secret",
};

async function loadSecrets() {
  const entries = Object.entries(SECRETS);
  const values = await Promise.all(
    entries.map(([, secretName]) => fetchSecretByName(secretName))
  );
  return values;
}

// This used to be hidden by a broad src/server.js call-site exemption.
// The checker must now reject direct unallowlisted reads in server.js.
async function sneak() {
  return fetchSecretByName("not-allowlisted-secret");
}

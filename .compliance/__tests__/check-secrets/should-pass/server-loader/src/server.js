const SECRETS = {
  FOO_TOKEN: "foo-token-secret",
};

async function loadSecrets() {
  const entries = Object.entries(SECRETS);
  const values = await Promise.all(
    entries.map(([, secretName]) => fetchSecretByName(secretName))
  );
  for (let i = 0; i < entries.length; i++) {
    process.env[entries[i][0]] = values[i];
  }
}

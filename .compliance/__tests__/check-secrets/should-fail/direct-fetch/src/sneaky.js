// Direct fetchSecretByName call to a secret name that is NOT in
// secrets-allowlist.json#read or #aux_read. The checker must catch this.
const x = fetchSecretByName("not-allowlisted-secret");

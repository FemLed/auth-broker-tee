// Token-like env var read whose key is NOT in env_var_allowlist. The
// checker's check (C) must catch this even though no Secret Manager
// call is made.
const k = process.env.SNUCK_IN_API_KEY;

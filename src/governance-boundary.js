export const GOVERNANCE_SECURITY_BOUNDARY = {
  schema: "femled.tee.governance.security_boundary.v1",
  threatModel: {
    githubSuperUserTrusted: false,
    gcpOwnerTrusted: false,
    githubActionsTrustedForApproval: false,
    gcpKmsTrustedForGovernance: false,
    gcpKmsTrustedAsSignerProxy: false,
    gcpSecretManagerTrustedForGovernanceKeys: false,
    gcpCloudStorageTrustedForGovernanceState: false,
    trustedBoundary: "current Confidential Space TEE process memory plus Google hardware attestation; the governance signing key is generated in enclave memory and has no at-rest form",
  },
  invariants: [
    "No admin recovery path exists for governance private keys.",
    "Governance signing keys are generated in enclave memory and are never written to disk, Cloud Storage, Secret Manager or Cloud KMS, so no project administrator holds a key that can sign for the lineage.",
    "GitHub and GCP may build or deploy candidates, but cannot activate them without predecessor signature.",
    "AI first-principles approval is required but cannot override failed hard checks.",
    "Killing the active TEE before successor handoff bricks governance instead of enabling recovery.",
    "The OAuth redirect URI, scopes, project and route collection are image-pinned; launch metadata may only toggle the ACME renewer dry run.",
    "The TLS private key for oauth-tee.femled.ai is ephemeral: it is minted fresh in enclave memory on every boot and has no at-rest form (no sealed capsule, no KMS wrap, never in Secret Manager/GCS/disk), so a GCP project/org IAM owner has no ciphertext to decrypt. TLS confidentiality against a hostile owner is prevented, not merely audited.",
  ],
  nonGoals: [
    "Availability against a hostile GCP owner.",
    "Protection for legacy secrets still readable from GCP Secret Manager.",
    "Protection if genesis starts from a compromised TEE.",
  ],
};

export const SECRET_GOVERNANCE_CLASSIFICATION = {
  GOOGLE_CLIENT_ID: "public-or-low-sensitivity-identifier",
  GOOGLE_CLIENT_SECRET: "external-provider-static-secret-outside-guarantee-until-rotated",
  HMAC_SECRET: "tee-owned-rotatable-memory-only-candidate",
  BROKER_API_KEY: "tee-owned-only-after-tenant-rekey-handoff",
  GITHUB_APP_ID: "public-or-low-sensitivity-identifier",
  GITHUB_APP_PRIVATE_KEY: "external-provider-static-secret-outside-governance-guarantee",
  GITHUB_WEBHOOK_SECRET: "tee-owned-rotatable-memory-only-candidate",
  AUTH_BROKER_DEPLOY_ROUTE_BUNDLE_JSON: "signed-data-not-secret",
  APNS_COACH_AUTH_KEY_P8: "external-provider-static-secret-outside-guarantee-until-rotated",
  APNS_COACH_AUTH_KEY_ID: "public-or-low-sensitivity-identifier",
  APPLE_TEAM_ID: "public-or-low-sensitivity-identifier",
};

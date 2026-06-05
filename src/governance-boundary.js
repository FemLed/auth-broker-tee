export const GOVERNANCE_SECURITY_BOUNDARY = {
  schema: "femled.tee.governance.security_boundary.v1",
  threatModel: {
    githubSuperUserTrusted: false,
    gcpOwnerTrusted: false,
    githubActionsTrustedForApproval: false,
    gcpKmsTrustedForGovernance: false,
    gcpKmsTrustedAsSignerProxy: true,
    gcpSecretManagerTrustedForGovernanceKeys: false,
    gcpCloudStorageTrustedAsCapsuleTransport: true,
    trustedBoundary: "current Confidential Space TEE process memory plus Google hardware attestation; the governance signing key lives in Cloud KMS under attestation-bound WIF IAM but is never accessible as plaintext outside KMS",
  },
  invariants: [
    "No admin recovery path exists for governance private keys.",
    "Governance signing keys live exclusively in Cloud KMS under attestation-bound IAM (WIF principal scoped to the running image_digest), or in process memory for legacy/in-memory builds. Plaintext private key material is never extractable from KMS and never persisted to disk by the TEE.",
    "GitHub and GCP may build or deploy candidates, but cannot activate them without predecessor signature.",
    "AI first-principles approval is required but cannot override failed hard checks.",
    "Killing the active TEE before successor handoff bricks governance instead of enabling recovery.",
    "Governance state capsules persisted to GCS are encrypted application-side (AES-GCM with HKDF-derived key over a KMS witness signature bound to the AAD); the bucket is untrusted storage and the capsule AAD pins running image digest, KMS key version, lineage digest, epoch, and transferred state digest.",
    "Capsule restore requires the same image digest to attest via WIF, fetch the KMS public key, and observe that the lineage tail's signingKeyId equals the KMS-bound governanceKeyId; any mismatch falls back to inactive rather than restoring partial state.",
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

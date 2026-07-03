#!/usr/bin/env node
import { spawnSync } from "node:child_process";

export const PROJECT_ID = "prod-femled-couple-router";
export const PROJECT_NUMBER = "125139120897";
export const WIF_POOL_ID = "auth-broker-tee-pool";
export const ARTIFACT_LOCATION = "us-west1";
export const ARTIFACT_REPOSITORY = "auth-broker";
export const AUTH_BROKER_IMAGE_REPOSITORY = "auth-broker-tee";

export const SECRET_ACCESSOR_SECRETS = Object.freeze([
  "cloudflare-access-google-oauth-client-id",
  "cloudflare-access-google-oauth-client-secret",
  "auth-broker-hmac-secret",
  "broker-api-key",
  "auth-broker-tee-acme-account-key",
  "femled-code-agent-github-app-id",
  "femled-code-agent-github-app-private-key",
  "github-org-webhook-secret",
  "auth-broker-deploy-route-bundle",
  "APNS_COACH_AUTH_KEY_P8",
  "APNS_COACH_AUTH_KEY_ID",
  "APPLE_TEAM_ID",
]);

export const SECRET_VERSION_ADDER_SECRETS = Object.freeze([
  "auth-broker-tee-acme-account-key",
]);

// TLS is ephemeral: a candidate mints its own in-enclave cert at boot, so it
// needs NO TLS-sealing KMS unwrap and NO TLS-capsule object grant (there is no
// capsule). Plaintext TLS keys are never stored in Secret Manager or GCS. The
// governance state capsule bucket is still shared for genesis-only grants
// (governance capsules + latest-pointer).
export const CAPSULE_BUCKET = "prod-femled-couple-router-auth-broker-tee-governance-capsules";

// Genesis-only resources. A SUCCESSOR candidate receives its governance key and
// transferred state in-enclave and carries its TLS cert over, so it needs none
// of these at candidate stage. A self-attested GENESIS mints everything fresh:
// it signs its own genesis certificate (governance-signer), mints its first TLS
// cert via DNS-01 (renewer-governance-signer), and writes its first state
// capsule + latest-pointer to the capsule bucket. These mirror the Terraform
// `*_candidates` resources and are only granted with --genesis.
export const GOVERNANCE_SIGNER_KMS_KEY = Object.freeze({
  keyRing: "auth-broker-governance",
  key: "governance-signer",
  location: "us-west1",
});
export const RENEWER_SIGNER_KMS_KEY = Object.freeze({
  keyRing: "auth-broker-acme-renewer",
  key: "renewer-governance-signer",
  location: "us-west1",
});
export const CAPSULE_POINTER_OBJECT = "capsules/latest-pointer.json";

const VALID_OPERATIONS = new Set(["grant", "revoke"]);

export function parseArgs(argv = process.argv.slice(2)) {
  const options = {
    operation: "",
    candidateImageDigest: "",
    dryRun: false,
    genesis: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`${arg} requires a value`);
      return argv[i];
    };
    if (arg === "--operation") options.operation = next();
    else if (arg === "--candidate-image-digest") options.candidateImageDigest = next();
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--genesis") options.genesis = true;
    else if (arg === "--help" || arg === "-h") options.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

export function candidateWifPrincipal(candidateImageDigest) {
  if (!isSha256Digest(candidateImageDigest)) {
    throw new Error("candidate image digest must be sha256:<64 lowercase hex chars>");
  }
  return `principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_ID}/attribute.image_digest/${candidateImageDigest}`;
}

export function buildIamOperations({ operation, candidateImageDigest, genesis = false }) {
  if (!VALID_OPERATIONS.has(operation)) {
    throw new Error("operation must be grant or revoke");
  }
  const member = candidateWifPrincipal(candidateImageDigest);
  const secretCommand = operation === "grant"
    ? "add-iam-policy-binding"
    : "remove-iam-policy-binding";
  const artifactCommand = operation === "grant"
    ? "add-iam-policy-binding"
    : "remove-iam-policy-binding";

  const operations = [
    ...SECRET_ACCESSOR_SECRETS.map((secret) => ({
      kind: "secret",
      resource: secret,
      role: "roles/secretmanager.secretAccessor",
      command: [
        "secrets",
        secretCommand,
        secret,
        `--project=${PROJECT_ID}`,
        `--member=${member}`,
        "--role=roles/secretmanager.secretAccessor",
        "--quiet",
      ],
    })),
    ...SECRET_VERSION_ADDER_SECRETS.map((secret) => ({
      kind: "secret",
      resource: secret,
      role: "roles/secretmanager.secretVersionAdder",
      command: [
        "secrets",
        secretCommand,
        secret,
        `--project=${PROJECT_ID}`,
        `--member=${member}`,
        "--role=roles/secretmanager.secretVersionAdder",
        "--quiet",
      ],
    })),
    {
      kind: "artifactRepository",
      resource: `${PROJECT_ID}/${ARTIFACT_LOCATION}/${ARTIFACT_REPOSITORY}`,
      role: "roles/artifactregistry.reader",
      command: [
        "artifacts",
        "repositories",
        artifactCommand,
        ARTIFACT_REPOSITORY,
        `--project=${PROJECT_ID}`,
        `--location=${ARTIFACT_LOCATION}`,
        `--member=${member}`,
        "--role=roles/artifactregistry.reader",
        "--quiet",
      ],
    },
    // Ephemeral TLS: EVERY candidate (successor or genesis) mints its own
    // in-enclave cert at boot, so it needs the renewer-governance-signer to sign
    // the DNS-01 renewer envelope to authoritative-dns-tee. (Under the old
    // sealed-TLS model a successor carried the cert over and needed no signer at
    // boot; that carry-over is gone.) Governance-signer + capsule bucket writes
    // remain genesis-only -- a successor receives its governance identity/state
    // through the predecessor-signed activation bundle, not by minting genesis.
    kmsKeyGrant(RENEWER_SIGNER_KMS_KEY, "roles/cloudkms.signerVerifier", secretCommand, member),
    kmsKeyGrant(RENEWER_SIGNER_KMS_KEY, "roles/cloudkms.viewer", secretCommand, member),
  ];

  if (genesis) {
    operations.push(...genesisOnlyOperations({ command: secretCommand, member }));
  }
  return operations;
}

function kmsKeyGrant(keySpec, role, command, member) {
  return {
    kind: "kmsKey",
    resource: `${keySpec.keyRing}/${keySpec.key}`,
    role,
    command: [
      "kms", "keys", command, keySpec.key,
      `--keyring=${keySpec.keyRing}`,
      `--location=${keySpec.location}`,
      `--project=${PROJECT_ID}`,
      `--member=${member}`,
      `--role=${role}`,
      "--condition=None",
      "--quiet",
    ],
  };
}

// Bindings a self-attested GENESIS needs that a SUCCESSOR does not: sign its own
// genesis cert (governance-signer) and write its first state capsule +
// latest-pointer to the capsule bucket. (The renewer-governance-signer needed to
// mint TLS at boot is granted to ALL candidates in the base set now that TLS is
// ephemeral, so it is not repeated here.) Mirrors the Terraform `*_candidates`
// resources. Granted only with --genesis; revoked after promotion.
function genesisOnlyOperations({ command, member }) {
  const bucketRole = (role) => ({
    kind: "bucket",
    resource: CAPSULE_BUCKET,
    role,
    command: [
      "storage", "buckets", command, `gs://${CAPSULE_BUCKET}`,
      `--member=${member}`,
      `--role=${role}`,
      "--condition=None",
      "--quiet",
    ],
  });
  return [
    kmsKeyGrant(GOVERNANCE_SIGNER_KMS_KEY, "roles/cloudkms.signerVerifier", command, member),
    kmsKeyGrant(GOVERNANCE_SIGNER_KMS_KEY, "roles/cloudkms.viewer", command, member),
    bucketRole("roles/storage.objectViewer"),
    bucketRole("roles/storage.objectCreator"),
    {
      kind: "bucket",
      resource: `${CAPSULE_BUCKET}/${CAPSULE_POINTER_OBJECT}`,
      role: "roles/storage.objectAdmin",
      command: [
        "storage", "buckets", command, `gs://${CAPSULE_BUCKET}`,
        `--member=${member}`,
        "--role=roles/storage.objectAdmin",
        `--condition=expression=resource.name.endsWith("/objects/${CAPSULE_POINTER_OBJECT}"),title=Latest pointer object only (candidate)`,
        "--quiet",
      ],
    },
  ];
}

export function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

function runGcloud(args) {
  const result = spawnSync("gcloud", args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`gcloud ${args.join(" ")} failed: ${result.stderr || result.stdout}`);
  }
}

function usage() {
  return `Usage: node scripts/reconcile-candidate-resource-iam.mjs --operation <grant|revoke> --candidate-image-digest <sha256:digest> [--dry-run] [--genesis]
  --genesis  also grant/revoke the genesis-only bindings (governance-signer + renewer-signer signerVerifier/viewer, capsule reader/writer/latest-pointer). Required for a self-attested operator genesis; omit for successor candidates.`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const options = parseArgs();
    if (options.help) {
      console.log(usage());
      process.exit(0);
    }
    const operations = buildIamOperations(options);
    const report = {
      schema: "femled.auth_broker.candidate_resource_iam_reconciliation.v1",
      operation: options.operation,
      candidateImageDigest: options.candidateImageDigest,
      candidateMember: candidateWifPrincipal(options.candidateImageDigest),
      dryRun: options.dryRun,
      genesis: options.genesis,
      operations: operations.map(({ command, ...summary }) => summary),
    };
    if (!options.dryRun) {
      for (const op of operations) runGcloud(op.command);
    }
    console.log(JSON.stringify(report, null, 2));
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  ARTIFACT_REPOSITORY,
  buildIamOperations,
  candidateWifPrincipal,
  SECRET_ACCESSOR_SECRETS,
  SECRET_VERSION_ADDER_SECRETS,
} from "../scripts/reconcile-candidate-resource-iam.mjs";

const DIGEST = "sha256:" + "a".repeat(64);

test("candidate resource IAM script constructs only expected bindings", () => {
  const operations = buildIamOperations({
    operation: "grant",
    candidateImageDigest: DIGEST,
  });
  const member = candidateWifPrincipal(DIGEST);

  // Ephemeral TLS: a successor candidate mints its own in-enclave cert at boot,
  // so it gets NO TLS-sealing KMS or TLS-capsule bucket grant. It DOES need the
  // renewer-governance-signer (signerVerifier + viewer) to sign the DNS-01
  // renewer envelope for that boot mint, plus secrets (accessor + adder) and
  // Artifact Registry reader.
  assert.equal(operations.length, SECRET_ACCESSOR_SECRETS.length + SECRET_VERSION_ADDER_SECRETS.length + 3);
  assert.ok(operations.every((operation) => operation.command.some((part) => part === `--member=${member}`)));

  const secretAccessorOps = operations.filter((operation) => operation.role === "roles/secretmanager.secretAccessor");
  assert.deepEqual(secretAccessorOps.map((operation) => operation.resource), [...SECRET_ACCESSOR_SECRETS]);
  assert.ok(!secretAccessorOps.some((operation) => /tls/.test(operation.resource)),
    "TLS material must never be granted via Secret Manager");

  const secretWriterOps = operations.filter((operation) => operation.role === "roles/secretmanager.secretVersionAdder");
  assert.deepEqual(secretWriterOps.map((operation) => operation.resource), [...SECRET_VERSION_ADDER_SECRETS]);
  assert.ok(!secretWriterOps.some((operation) => /tls/.test(operation.resource)),
    "TLS material must never be written to Secret Manager");

  // The only KMS grants a successor candidate gets are the renewer signer
  // (signerVerifier + viewer). The retired tls-sealing key and the
  // governance-signer (genesis-only) must NOT appear.
  const kmsOps = operations.filter((operation) => operation.kind === "kmsKey");
  assert.equal(kmsOps.length, 2);
  assert.ok(kmsOps.every((operation) => /renewer-governance-signer$/.test(operation.resource)),
    "successor candidate KMS grants must be the renewer signer only");
  assert.deepEqual(
    kmsOps.map((operation) => operation.role).sort(),
    ["roles/cloudkms.signerVerifier", "roles/cloudkms.viewer"],
  );
  assert.ok(!operations.some((operation) => /tls-sealing/.test(operation.resource)),
    "the retired tls-sealing key must never be granted to a candidate");
  assert.ok(!operations.some((operation) => /tls-capsule/.test(operation.resource)),
    "there is no TLS capsule to grant object access to");
  assert.ok(!operations.some((operation) => /\/governance-signer$/.test(operation.resource)),
    "governance-signer is genesis-only; a successor receives its identity via the activation bundle");

  const artifactOps = operations.filter((operation) => operation.kind === "artifactRepository");
  assert.equal(artifactOps.length, 1);
  assert.match(artifactOps[0].resource, new RegExp(`${ARTIFACT_REPOSITORY}$`));
  assert.equal(artifactOps[0].role, "roles/artifactregistry.reader");
});

test("genesis candidate additionally gets governance-signer + capsule bucket writes", () => {
  const successor = buildIamOperations({ operation: "grant", candidateImageDigest: DIGEST });
  const genesis = buildIamOperations({ operation: "grant", candidateImageDigest: DIGEST, genesis: true });
  assert.ok(genesis.length > successor.length, "genesis needs strictly more bindings than a successor");
  // Genesis mints its own genesis certificate -> governance-signer signerVerifier.
  assert.ok(genesis.some((operation) => /\/governance-signer$/.test(operation.resource) && operation.role === "roles/cloudkms.signerVerifier"),
    "genesis must be able to sign its own genesis certificate");
  // Genesis writes its first governance capsule + latest-pointer.
  assert.ok(genesis.some((operation) => operation.kind === "bucket" && operation.role === "roles/storage.objectCreator"),
    "genesis must be able to write its first governance capsule");
});

test("candidate resource IAM script rejects arbitrary operations and invalid digests", () => {
  assert.throws(
    () => buildIamOperations({ operation: "set-owner", candidateImageDigest: DIGEST }),
    /operation must be grant or revoke/
  );
  assert.throws(
    () => candidateWifPrincipal("sha256:" + "g".repeat(64)),
    /candidate image digest/
  );
});

test("candidate project role reconciler dry-run allowlists roles and member shape", () => {
  const result = spawnSync("bash", ["scripts/reconcile-candidate-project-roles.sh"], {
    encoding: "utf8",
    env: {
      ...process.env,
      DRY_RUN: "true",
      RECONCILE_OPERATION: "grant",
      CANDIDATE_IMAGE_DIGEST: DIGEST,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report.roles, [
    "roles/aiplatform.user",
    "roles/serviceusage.serviceUsageConsumer",
  ]);
  assert.equal(report.candidateImageDigest, DIGEST);
  assert.match(report.memberDigest, /^sha256:[a-f0-9]{64}$/);
});

test("candidate project role reconciler rejects invalid operation and digest", () => {
  const invalidOperation = spawnSync("bash", ["scripts/reconcile-candidate-project-roles.sh"], {
    encoding: "utf8",
    env: {
      ...process.env,
      DRY_RUN: "true",
      RECONCILE_OPERATION: "owner",
      CANDIDATE_IMAGE_DIGEST: DIGEST,
    },
  });
  assert.notEqual(invalidOperation.status, 0);
  assert.match(invalidOperation.stderr, /grant or revoke/);

  const invalidDigest = spawnSync("bash", ["scripts/reconcile-candidate-project-roles.sh"], {
    encoding: "utf8",
    env: {
      ...process.env,
      DRY_RUN: "true",
      RECONCILE_OPERATION: "grant",
      CANDIDATE_IMAGE_DIGEST: "latest",
    },
  });
  assert.notEqual(invalidDigest.status, 0);
  assert.match(invalidDigest.stderr, /sha256/);
});

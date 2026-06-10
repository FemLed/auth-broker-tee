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

  // secrets + sealed-TLS continuity (KMS sealing key + capsule object) + AR.
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

  const kmsOps = operations.filter((operation) => operation.kind === "kmsKey");
  assert.equal(kmsOps.length, 1);
  assert.equal(kmsOps[0].role, "roles/cloudkms.cryptoKeyEncrypterDecrypter");
  assert.match(kmsOps[0].resource, /tls-sealing$/);

  const bucketOps = operations.filter((operation) => operation.kind === "bucket");
  assert.equal(bucketOps.length, 1);
  assert.equal(bucketOps[0].role, "roles/storage.objectAdmin");
  assert.match(bucketOps[0].resource, /tls\/oauth-tee\.tls-capsule\.v1\.json$/);
  assert.ok(bucketOps[0].command.some((part) => part.includes("resource.name.endsWith")),
    "capsule objectAdmin must stay conditioned to the single TLS capsule object");

  const artifactOps = operations.filter((operation) => operation.kind === "artifactRepository");
  assert.equal(artifactOps.length, 1);
  assert.match(artifactOps[0].resource, new RegExp(`${ARTIFACT_REPOSITORY}$`));
  assert.equal(artifactOps[0].role, "roles/artifactregistry.reader");
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

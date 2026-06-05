import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const workflow = fs.readFileSync(".github/workflows/build-and-attest.yml", "utf8");
const dockerfile = fs.readFileSync("Dockerfile.repair-worker", "utf8");
const entrypoint = fs.readFileSync("repair-worker/entrypoint.sh", "utf8");
const runner = fs.readFileSync("repair-worker/repair-worker-run.py", "utf8");
const terraform = fs.readFileSync("terraform/repair-worker-job.tf", "utf8");

test("repair-worker image is built as a separate non-TEE artifact", () => {
  assert.match(workflow, /REPAIR_WORKER_IMAGE_NAME:\s+auth-broker-tee-repair-worker/);
  assert.match(workflow, /Dockerfile\.repair-worker/);
  assert.match(workflow, /repair_worker_image_digest/);
  assert.match(workflow, /Repair-worker image digest/);
});

test("repair-worker runtime has minimal native tooling but avoids tenant code-agent extras", () => {
  assert.match(dockerfile, /build-essential/);
  assert.match(dockerfile, /\bgit\b/);
  assert.match(dockerfile, /\bcurl\b/);
  assert.match(dockerfile, /\bjq\b/);
  assert.match(dockerfile, /\bripgrep\b/);
  assert.doesNotMatch(dockerfile, /xvfb|x11vnc|chromium|terraform/i);
  assert.match(dockerfile, /USER repair/);
  assert.doesNotMatch(entrypoint, /\$\{!/, "entrypoint must stay POSIX sh compatible");
  assert.equal(entrypoint.includes('eval "value=\\${$required:-}"'), true);
});

test("repair-worker Vertex model calls use Google Search grounding", () => {
  assert.match(runner, /"tools":\s*\[\{"googleSearch":\s*\{\}\}\]/);
});

test("repair-worker Terraform keeps untrusted worker and launcher roles narrow", () => {
  assert.match(terraform, /variable "enable_repair_worker"/);
  assert.match(terraform, /data "external" "repair_worker_image_digest"/);
  assert.match(terraform, /roles\/aiplatform\.user/);
  assert.match(terraform, /roles\/artifactregistry\.reader/);
  assert.match(terraform, /roles\/cloudbuild\.builds\.viewer/);
  assert.match(terraform, /roles\/logging\.logWriter/);
  assert.match(terraform, /run\.jobs\.runWithOverrides/);

  for (const forbidden of [
    "roles/editor",
    "roles/owner",
    "roles/secretmanager.secretAccessor",
    "roles/secretmanager.secretVersionAdder",
    "roles/cloudkms.signerVerifier",
    "roles/run.admin",
    "roles/iam.serviceAccountAdmin",
  ]) {
    assert.equal(terraform.includes(forbidden), false, `repair worker must not grant ${forbidden}`);
  }
});

#!/usr/bin/env bash
set -euo pipefail
#
# Post-genesis promotion + cleanup for auth-broker-tee (first-class genesis).
#
# Run AFTER operator-genesis.yml has produced an active, epoch-1 TEE on the new
# image digest and DNS has been cut over to it. This script:
#
#   1. Revokes the RETIRED (previously-active) image digest's WIF access so the
#      dead lineage's principalSet can no longer read secrets / sign / write.
#      The NEW (now-active) digest KEEPS its bindings -- the candidate window
#      that operator-genesis opened IS the active access (same image-digest
#      principalSet), so we never revoke the new digest.
#   2. Repoints FIRST_PRINCIPLES_TEE_EXPECTED_IMAGE_DIGEST to the new digest so
#      future PR/push first-principles reviews verify against the new live TEE.
#   3. Unsets the bootstrap-bypass repo variables (ALLOW_AUTH_BROKER_TEE_BOOTSTRAP_BUILD
#      and AUTH_BROKER_TEE_BOOTSTRAP_COMMIT_SHA) so the active-TEE review gate is
#      fully back in force.
#   4. Updates the bookkeeping tfvars (container_image_digest=new,
#      candidate_image_digests=[]).
#
# Requires: gcloud (authed), gh (authed for repo variables), node.
#
# Usage:
#   scripts/promote-genesis.sh --image-digest sha256:<new> --retire-digest sha256:<old> [--dry-run]

PROJECT_ID="${PROJECT_ID:-prod-femled-couple-router}"
REPO="${REPO:-FemLed/auth-broker-tee}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECONCILED_TFVARS="${SCRIPT_DIR}/../terraform/active-tee.reconciled.auto.tfvars.json"

NEW_DIGEST=""
RETIRE_DIGEST=""
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image-digest) NEW_DIGEST="$2"; shift 2 ;;
    --retire-digest) RETIRE_DIGEST="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help)
      echo "Usage: $0 --image-digest sha256:<new> --retire-digest sha256:<old> [--dry-run]"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ ! "${NEW_DIGEST}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo "::error::--image-digest must be sha256:<64 hex>" >&2; exit 64
fi
if [[ ! "${RETIRE_DIGEST}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo "::error::--retire-digest must be sha256:<64 hex>" >&2; exit 64
fi
if [[ "${NEW_DIGEST}" == "${RETIRE_DIGEST}" ]]; then
  echo "::error::--image-digest and --retire-digest must differ" >&2; exit 64
fi

run() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[dry-run] $*"
  else
    echo "+ $*"
    "$@"
  fi
}

echo "==> Promoting genesis digest ${NEW_DIGEST}; retiring ${RETIRE_DIGEST} (dry-run=${DRY_RUN})"

# 1. Revoke the retired image's WIF access (shape-agnostic).
#    The retired digest may have been granted via the active-tee path OR the
#    candidate --genesis path, and an activated predecessor ACCUMULATES BOTH
#    active- and candidate-titled conditioned bindings (e.g. "Latest pointer
#    object only" AND "Latest pointer object only (candidate)"). So we cannot
#    assume any single grant shape: instead of replaying a grant-shaped revoke
#    (which aborts the moment one binding's condition/title does not match), we
#    remove the retired principalSet member from EVERY binding on each resource
#    regardless of role/condition/title, tolerate already-absent bindings, and
#    verify zero residual references. The resource set is single-sourced from
#    reconcile-candidate-resource-iam.mjs so it cannot drift.
echo "--- revoke retired digest WIF access (shape-agnostic) ---"
if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[dry-run] strip principalSet for ${RETIRE_DIGEST} from every binding across secrets/KMS/capsule-bucket/artifact/project, then verify 0 residual"
else
  RECONCILER_PATH="${SCRIPT_DIR}/reconcile-candidate-resource-iam.mjs" \
  RETIRE_DIGEST="${RETIRE_DIGEST}" \
  node --input-type=module <<'NODE'
import { spawnSync } from "node:child_process";
import fs from "node:fs";

const recon = await import(process.env.RECONCILER_PATH);
const {
  PROJECT_ID, ARTIFACT_LOCATION, ARTIFACT_REPOSITORY,
  SECRET_ACCESSOR_SECRETS, SECRET_VERSION_ADDER_SECRETS,
  TLS_SEALING_KMS_KEY, GOVERNANCE_SIGNER_KMS_KEY, RENEWER_SIGNER_KMS_KEY,
  TLS_CAPSULE_BUCKET, candidateWifPrincipal,
} = recon;

const digest = process.env.RETIRE_DIGEST;
const member = candidateWifPrincipal(digest);
let failed = false;

function gcloud(args) {
  const r = spawnSync("gcloud", args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  return { ok: r.status === 0, stdout: r.stdout || "", stderr: r.stderr || "" };
}
const oneLine = (s) => String(s).replace(/\s+/g, " ").trim().slice(0, 200);

// Resource-level IAM: get-iam-policy -> drop `member` from every binding ->
// set-iam-policy. Each descriptor knows its own gcloud get/set forms.
const secretNames = [...new Set([...SECRET_ACCESSOR_SECRETS, ...SECRET_VERSION_ADDER_SECRETS])];
const resources = [
  ...secretNames.map((s) => ({
    label: `secret ${s}`,
    get: ["secrets", "get-iam-policy", s, `--project=${PROJECT_ID}`],
    set: (f) => ["secrets", "set-iam-policy", s, f, `--project=${PROJECT_ID}`],
  })),
  ...[TLS_SEALING_KMS_KEY, GOVERNANCE_SIGNER_KMS_KEY, RENEWER_SIGNER_KMS_KEY].map((k) => ({
    label: `kms ${k.keyRing}/${k.key}`,
    get: ["kms", "keys", "get-iam-policy", k.key, `--keyring=${k.keyRing}`, `--location=${k.location}`, `--project=${PROJECT_ID}`],
    set: (f) => ["kms", "keys", "set-iam-policy", k.key, f, `--keyring=${k.keyRing}`, `--location=${k.location}`, `--project=${PROJECT_ID}`],
  })),
  {
    label: `bucket ${TLS_CAPSULE_BUCKET}`,
    get: ["storage", "buckets", "get-iam-policy", `gs://${TLS_CAPSULE_BUCKET}`],
    set: (f) => ["storage", "buckets", "set-iam-policy", `gs://${TLS_CAPSULE_BUCKET}`, f],
  },
  {
    label: `artifact ${ARTIFACT_REPOSITORY}`,
    get: ["artifacts", "repositories", "get-iam-policy", ARTIFACT_REPOSITORY, `--location=${ARTIFACT_LOCATION}`, `--project=${PROJECT_ID}`],
    set: (f) => ["artifacts", "repositories", "set-iam-policy", ARTIFACT_REPOSITORY, f, `--location=${ARTIFACT_LOCATION}`, `--project=${PROJECT_ID}`],
  },
];

function stripFromResource(res) {
  const got = gcloud([...res.get, "--format=json"]);
  if (!got.ok) { console.log(`  [skip] ${res.label}: get-iam-policy failed: ${oneLine(got.stderr)}`); return; }
  let policy;
  try { policy = JSON.parse(got.stdout); } catch { console.log(`  [skip] ${res.label}: unparseable policy`); return; }
  const before = JSON.stringify(policy.bindings || []);
  policy.bindings = (policy.bindings || [])
    .map((b) => ({ ...b, members: (b.members || []).filter((m) => m !== member) }))
    .filter((b) => (b.members || []).length > 0);
  if (JSON.stringify(policy.bindings) === before) { console.log(`  [ok] ${res.label}: no binding for retired digest`); return; }
  const tmp = `/tmp/promote-revoke-${process.pid}-${Math.random().toString(36).slice(2)}.json`;
  fs.writeFileSync(tmp, JSON.stringify(policy));
  const set = gcloud([...res.set(tmp), "--format=none"]);
  try { fs.unlinkSync(tmp); } catch { /* ignore */ }
  if (!set.ok) { console.log(`  [FAIL] ${res.label}: set-iam-policy failed: ${oneLine(set.stderr)}`); failed = true; return; }
  console.log(`  [revoked] ${res.label}`);
}

console.log(`Revoking WIF member for retired digest:\n  ${member}`);
for (const res of resources) stripFromResource(res);

// Project-level roles (unconditioned; mirrors reconcile-candidate-project-roles.sh).
for (const role of ["roles/aiplatform.user", "roles/serviceusage.serviceUsageConsumer"]) {
  const r = gcloud(["projects", "remove-iam-policy-binding", PROJECT_ID, `--member=${member}`, `--role=${role}`, "--condition=None", "--quiet", "--format=none"]);
  if (r.ok) console.log(`  [revoked] project ${role}`);
  else if (/not found/i.test(r.stderr)) console.log(`  [ok] project ${role}: no binding for retired digest`);
  else { console.log(`  [FAIL] project ${role}: ${oneLine(r.stderr)}`); failed = true; }
}

// Verify zero residual references to the retired digest.
let residual = 0;
for (const res of resources) {
  const got = gcloud([...res.get, "--format=json"]);
  if (got.ok && got.stdout.includes(digest)) { console.log(`  [residual] ${res.label} still references ${digest}`); residual += 1; }
}
const proj = gcloud(["projects", "get-iam-policy", PROJECT_ID, "--format=json"]);
if (proj.ok && proj.stdout.includes(digest)) { console.log(`  [residual] project policy still references ${digest}`); residual += 1; }

if (failed || residual > 0) {
  console.error(`Retire revoke INCOMPLETE (failed=${failed}, residual=${residual}); resolve before continuing promotion.`);
  process.exit(1);
}
console.log("Retire revoke complete: 0 residual references to the retired digest.");
NODE
fi

# 2. Repoint the first-principles expected-image-digest to the new live TEE.
echo "--- repoint FIRST_PRINCIPLES_TEE_EXPECTED_IMAGE_DIGEST ---"
run gh variable set FIRST_PRINCIPLES_TEE_EXPECTED_IMAGE_DIGEST --repo "${REPO}" --body "${NEW_DIGEST}"

# 3. Restore the active-TEE review gate: drop the bootstrap-bypass variables.
echo "--- unset bootstrap-bypass repo variables ---"
run gh variable delete ALLOW_AUTH_BROKER_TEE_BOOTSTRAP_BUILD --repo "${REPO}"
run gh variable delete AUTH_BROKER_TEE_BOOTSTRAP_COMMIT_SHA --repo "${REPO}"

# 4. Bookkeeping: the new digest is the active image; no candidate window open.
echo "--- update bookkeeping tfvars ---"
if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[dry-run] write ${RECONCILED_TFVARS} container_image_digest=${NEW_DIGEST} candidate_image_digests=[]"
else
  printf '{\n  "container_image_digest": "%s",\n  "candidate_image_digests": []\n}\n' "${NEW_DIGEST}" > "${RECONCILED_TFVARS}"
  echo "wrote ${RECONCILED_TFVARS}"
fi

echo "==> Promotion complete. The NEW digest keeps its (now-active) WIF bindings."
echo "    Remaining manual steps: confirm DNS points at the new VM, then delete the"
echo "    old VM with: gcloud compute instances delete <old-vm> --zone=us-west1-b --project=${PROJECT_ID}"

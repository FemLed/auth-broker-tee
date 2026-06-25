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

# 1. Revoke the retired image's full WIF access (resource IAM + project roles).
echo "--- revoke retired digest WIF access ---"
run node "${SCRIPT_DIR}/reconcile-candidate-resource-iam.mjs" \
  --operation revoke --genesis --candidate-image-digest "${RETIRE_DIGEST}"
run gcloud run jobs execute auth-broker-candidate-role-reconciler \
  --project="${PROJECT_ID}" --region=us-west1 --wait \
  --update-env-vars="RECONCILE_OPERATION=revoke,CANDIDATE_IMAGE_DIGEST=${RETIRE_DIGEST}"

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

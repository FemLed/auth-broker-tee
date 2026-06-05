#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-prod-femled-couple-router}"
PROJECT_NUMBER="${PROJECT_NUMBER:-125139120897}"
WIF_POOL_ID="${WIF_POOL_ID:-auth-broker-tee-pool}"
OPERATION="${RECONCILE_OPERATION:-${1:-}}"
CANDIDATE_IMAGE_DIGEST="${CANDIDATE_IMAGE_DIGEST:-${2:-}}"
DRY_RUN="${DRY_RUN:-false}"

if [[ "${OPERATION}" != "grant" && "${OPERATION}" != "revoke" ]]; then
  echo "RECONCILE_OPERATION must be grant or revoke" >&2
  exit 64
fi

if [[ ! "${CANDIDATE_IMAGE_DIGEST}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo "CANDIDATE_IMAGE_DIGEST must be sha256:<64 lowercase hex chars>" >&2
  exit 64
fi

MEMBER="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_ID}/attribute.image_digest/${CANDIDATE_IMAGE_DIGEST}"
MEMBER_DIGEST="$(printf '%s' "${MEMBER}" | sha256sum | cut -d' ' -f1)"
ROLES=(
  "roles/aiplatform.user"
  "roles/serviceusage.serviceUsageConsumer"
)

if [[ "${OPERATION}" == "grant" ]]; then
  GCLOUD_IAM_COMMAND="add-iam-policy-binding"
else
  GCLOUD_IAM_COMMAND="remove-iam-policy-binding"
fi

printf '{"schema":"femled.auth_broker.candidate_project_role_reconciliation.v1","operation":"%s","candidateImageDigest":"%s","memberDigest":"sha256:%s","roles":[' \
  "${OPERATION}" "${CANDIDATE_IMAGE_DIGEST}" "${MEMBER_DIGEST}"
for index in "${!ROLES[@]}"; do
  if [[ "${index}" != "0" ]]; then printf ','; fi
  printf '"%s"' "${ROLES[$index]}"
done
printf '],"dryRun":%s}\n' "$(if [[ "${DRY_RUN}" == "true" ]]; then echo true; else echo false; fi)"

if [[ "${DRY_RUN}" == "true" ]]; then
  exit 0
fi

for role in "${ROLES[@]}"; do
  # The project IAM policy contains conditional bindings (other TEEs / WIF
  # principals), so gcloud refuses an unconditioned add/remove in
  # non-interactive mode unless --condition is explicit. The candidate
  # project-role grants are intentionally unconditional, matching the
  # Terraform-managed candidate_wif_* bindings, so pin --condition=None.
  gcloud projects "${GCLOUD_IAM_COMMAND}" "${PROJECT_ID}" \
    --member="${MEMBER}" \
    --role="${role}" \
    --condition=None \
    --quiet >/dev/null
done

# ---------------------------------------------------------------------------
# Supply-chain attestation: GitHub Actions -> Artifact Registry push
#
# WIF pool + provider that lets the build-and-attest.yml workflow on the
# canonical repo + branch authenticate to GCP without any long-lived
# service account key. The attribute_condition pins the OIDC claim
# subject to *exactly* this workflow on this branch in this repo, so
# nothing else (no other workflow, no other repo, no PR fork, no
# manually-issued personal token) can impersonate the publisher.
#
# Mirror of the GitHub OIDC `job_workflow_ref` claim:
#   <repo>/<workflow_path>@<branch>
# e.g. "FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master"
# ---------------------------------------------------------------------------

locals {
  gh_workflow_subject = "${var.gh_repo}/${var.gh_workflow_path}@${var.gh_branch_ref}"

  # Operator-authorized re-genesis workflow. Pinned to the same repo + branch
  # so the WIF principal still requires master, but allows the
  # workflow_dispatch trigger that build-and-attest deliberately rejects.
  # See .github/workflows/operator-genesis.yml for the use case (broken-
  # continuity rollout of governance state capsule persistence).
  gh_operator_genesis_workflow_subject = "${var.gh_repo}/.github/workflows/operator-genesis.yml@${var.gh_branch_ref}"

  gh_publisher_workflow_subjects = [
    local.gh_workflow_subject,
    local.gh_operator_genesis_workflow_subject,
  ]

  # Sigstore keyless cert SAN that cosign embeds when GHA OIDC is the issuer.
  # This is what the verifier (and, optionally, Confidential Space launch
  # policy and WIF condition) match against.
  fulcio_san = "https://github.com/${var.gh_repo}/${var.gh_workflow_path}@${var.gh_branch_ref}"
}

# ---------------------------------------------------------------------------
# WIF pool dedicated to GitHub Actions
# ---------------------------------------------------------------------------
resource "google_iam_workload_identity_pool" "gh_actions" {
  workload_identity_pool_id = "gh-actions-pool"
  display_name              = "GitHub Actions for FemLed repos"
  description               = "Federated identities for GitHub Actions workflows that publish images and run admin tasks"

  depends_on = [google_project_service.iam_credentials]
}

resource "google_iam_workload_identity_pool_provider" "github_oidc" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.gh_actions.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub Actions OIDC"
  description                        = "Trusts token.actions.githubusercontent.com for the build-and-attest workflow only"

  oidc {
    issuer_uri = var.sigstore_oidc_issuer
    # Audience is "https://github.com/${var.gh_repo}/<owner>" by default in
    # google-github-actions/auth@v2; we accept the default audience that
    # action sends.
    allowed_audiences = []
  }

  attribute_mapping = {
    "google.subject"         = "assertion.sub"
    "attribute.repository"   = "assertion.repository"
    "attribute.ref"          = "assertion.ref"
    "attribute.workflow_ref" = "assertion.job_workflow_ref"
    "attribute.event_name"   = "assertion.event_name"
    "attribute.actor"        = "assertion.actor"
    "attribute.run_id"       = "assertion.run_id"
  }

  # Pin to: exact repo, exact branch, AND a narrow allow-list of (workflow,
  # event_name) pairs. No other workflow, no PR run, no fork can mint a token
  # through this provider. Currently allowed:
  #   - build-and-attest.yml on push (the publisher path)
  #   - operator-genesis.yml on workflow_dispatch (operator-authorized
  #     broken-continuity re-genesis; carries the explicit operator_statement
  #     gate enforced inside the workflow body)
  attribute_condition = join(" && ", [
    "assertion.repository == '${var.gh_repo}'",
    "assertion.ref == '${var.gh_branch_ref}'",
    "((assertion.job_workflow_ref == '${local.gh_workflow_subject}' && assertion.event_name == 'push') || (assertion.job_workflow_ref == '${local.gh_operator_genesis_workflow_subject}' && assertion.event_name == 'workflow_dispatch'))",
  ])

  depends_on = [google_project_service.sts]
}

# ---------------------------------------------------------------------------
# Publisher service account: scoped to AR writer on the auth-broker repo
#
# This SA can only push images to ${region}-docker.pkg.dev/.../auth-broker/*.
# It cannot read secrets, cannot impersonate other SAs, cannot touch the
# Confidential VM, cannot edit Terraform state.
# ---------------------------------------------------------------------------
resource "google_service_account" "gh_actions_publisher" {
  account_id   = "gh-actions-publisher"
  display_name = "GitHub Actions image publisher"
  description  = "Federated identity used by ${local.gh_workflow_subject} to push attested images"
}

resource "google_artifact_registry_repository_iam_member" "gh_actions_writer" {
  location   = var.region
  repository = google_artifact_registry_repository.auth_broker.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.gh_actions_publisher.email}"
}

# Allow the federated GHA principal to impersonate the publisher SA.
resource "google_service_account_iam_member" "gh_actions_wif_user" {
  service_account_id = google_service_account.gh_actions_publisher.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.gh_actions.workload_identity_pool_id}/attribute.workflow_ref/${local.gh_workflow_subject}"
}

# `google-github-actions/auth@v2` with `token_format = "access_token"`
# calls IAM Credentials `generateAccessToken`, which requires
# `iam.serviceAccounts.getAccessToken` in addition to
# workloadIdentityUser.
resource "google_service_account_iam_member" "gh_actions_token_creator" {
  service_account_id = google_service_account.gh_actions_publisher.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.gh_actions.workload_identity_pool_id}/attribute.workflow_ref/${local.gh_workflow_subject}"
}

# ---------------------------------------------------------------------------
# (KMS resources for the Confidential Space signed-image flow live in
# `kms.tf` -- separate file so the trust-load-bearing crypto-key + IAM
# grant can be reviewed in isolation.)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Outputs surfaced for the GitHub Actions workflow's
# google-github-actions/auth@v2 step
# ---------------------------------------------------------------------------
output "gh_actions_wif_provider" {
  description = "Full WIF provider resource path the GHA workflow passes to google-github-actions/auth@v2"
  value       = "projects/${var.project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.gh_actions.workload_identity_pool_id}/providers/${google_iam_workload_identity_pool_provider.github_oidc.workload_identity_pool_provider_id}"
}

output "gh_actions_publisher_sa_email" {
  description = "Service account email the GHA workflow impersonates"
  value       = google_service_account.gh_actions_publisher.email
}

output "fulcio_san_pinned_for_signing" {
  description = "The Fulcio cert SAN that cosign signatures will carry; verifiers and Confidential Space launch policy must match this exactly"
  value       = local.fulcio_san
}

output "gh_workflow_subject" {
  description = "Convenience copy of the GitHub OIDC job_workflow_ref claim that downstream tools key off"
  value       = local.gh_workflow_subject
}

# Note: KMS-related outputs (`image_signer_kms_key_uri`,
# `image_signer_fingerprint`, `image_signer_public_key_pem`) live next
# to the resource definitions in `kms.tf`.

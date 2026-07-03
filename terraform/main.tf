terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ---------------------------------------------------------------------------
# Enable required GCP APIs
# ---------------------------------------------------------------------------
resource "google_project_service" "compute" {
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "artifact_registry" {
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloud_build" {
  service            = "cloudbuild.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "secret_manager" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "confidential_computing" {
  service            = "confidentialcomputing.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam_credentials" {
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "sts" {
  service            = "sts.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "aiplatform" {
  service            = "aiplatform.googleapis.com"
  disable_on_destroy = false
}

# ---------------------------------------------------------------------------
# Artifact Registry
# ---------------------------------------------------------------------------
resource "google_artifact_registry_repository" "auth_broker" {
  location      = var.region
  repository_id = "auth-broker"
  format        = "DOCKER"
  description   = "Auth broker TEE container images"

  depends_on = [google_project_service.artifact_registry]
}

# ---------------------------------------------------------------------------
# Service Account for the Confidential VM workload
#
# This SA is attached to the VM. It needs:
#   - Artifact Registry read (to pull the container image)
#   - Confidential Computing workload user (to get attestation tokens)
#   - Log writer (for health/operational logs only -- launch policy blocks
#     workload stdout/stderr on production image)
#
# It does NOT get secretmanager.secretAccessor. Secret access is granted
# via WIF federated identity tied to the container image digest.
# ---------------------------------------------------------------------------
resource "google_service_account" "auth_broker_vm" {
  account_id   = "auth-broker-tee"
  display_name = "Auth Broker Confidential Space VM"
}

resource "google_project_iam_member" "broker_artifact_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.auth_broker_vm.email}"
}

resource "google_project_iam_member" "broker_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.auth_broker_vm.email}"
}

resource "google_project_iam_member" "broker_confidential_computing" {
  project = var.project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.auth_broker_vm.email}"
}

resource "google_project_iam_member" "broker_datastore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.auth_broker_vm.email}"
}

# ---------------------------------------------------------------------------
# Workload Identity Federation
#
# The WIF pool and provider allow the workload to authenticate using its
# Confidential Space attestation token. The attestation condition ensures
# only the expected container image digest running on a production
# Confidential Space image can obtain a federated access token.
#
# Per-secret IAM bindings below grant this federated identity access to
# specific Secret Manager secrets -- not a broad project-level role.
# ---------------------------------------------------------------------------
resource "google_iam_workload_identity_pool" "auth_broker" {
  workload_identity_pool_id = "auth-broker-tee-pool"
  display_name              = "Auth Broker TEE Pool"

  depends_on = [google_project_service.iam_credentials]
}

resource "google_iam_workload_identity_pool_provider" "attestation_verifier" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.auth_broker.workload_identity_pool_id
  workload_identity_pool_provider_id = "attestation-verifier"
  display_name                       = "CS Attestation Verifier"

  oidc {
    issuer_uri        = "https://confidentialcomputing.googleapis.com/"
    allowed_audiences = ["https://sts.googleapis.com"]
  }

  attribute_mapping = {
    "google.subject"         = "\"gcpcs::\"+assertion.submods.container.image_digest+\"::\"+assertion.submods.gce.project_number+\"::\"+assertion.submods.gce.instance_id"
    "attribute.image_digest" = "assertion.submods.container.image_digest"
  }

  # Base conditions: workload runs on a STABLE Confidential Space image in the
  # right project, attached to the broker SA.
  #
  # When var.enforce_signed_image_in_wif is true, the federated identity is
  # only minted if the attestation token exposes an image signature whose
  # `signature_algorithm:key_id` matches our Cosign KMS key. This is the
  # property Confidential Space's signed-image flow exposes (see
  # https://cloud.google.com/confidential-computing/confidential-space/docs/reference/attestation-assertions
  # under image_signatures). We deliberately do NOT use Fulcio SAN matching
  # here -- Confidential Space does not honor keyless Sigstore signatures
  # for this gate today; the keyless cert SAN check happens in the
  # standalone verifier binary against Rekor instead.
  #
  # The fingerprint is intentionally pinned via terraform.tfvars rather
  # than derived from the live KMS key. Rotating the signing key must be
  # an explicit Terraform diff, not an automatic follow-the-current-key
  # behavior.
  attribute_condition = join(" && ", concat(
    [
      "assertion.swname == 'CONFIDENTIAL_SPACE'",
      "'STABLE' in assertion.submods.confidential_space.support_attributes",
      "assertion.submods.gce.project_id == '${var.project_id}'",
      "'${google_service_account.auth_broker_vm.email}' in assertion.google_service_accounts",
    ],
    var.enforce_signed_image_in_wif ? [
      # Accept either the current fingerprint OR (if set) the previous
      # one. The list is built from `local.accepted_image_signer_celset`
      # so adding/removing a fingerprint is a single Terraform diff with
      # no fragile string surgery here.
      "${local.accepted_image_signer_celset}.exists(fingerprint, fingerprint in assertion.submods.container.image_signatures.map(sig, sig.signature_algorithm + ':' + sig.key_id))",
    ] : []
  ))

  depends_on = [google_project_service.sts]
}

# ---------------------------------------------------------------------------
# Secret Manager secret IDs
#
# These are pre-existing secret names, not secret payloads. Keep them as
# literals so digest-scoped IAM reconciliation does not require broad
# `secretmanager.secrets.get` metadata access just to derive known IDs.
# ---------------------------------------------------------------------------
locals {
  secret_ids = {
    google_client_id     = "cloudflare-access-google-oauth-client-id"
    google_client_secret = "cloudflare-access-google-oauth-client-secret"
    hmac_secret          = "auth-broker-hmac-secret"
    broker_api_key       = "broker-api-key"
    # The old auth-broker-tls-cert/-tls-key pair is fully retired AND deleted.
    # TLS material lives ONLY in enclave memory and is minted fresh on every
    # boot (ephemeral -- no sealed capsule, no KMS wrap); plaintext TLS keys are
    # never stored in Secret Manager or GCS.
    acme_account_key       = "auth-broker-tee-acme-account-key"
    github_app_id          = "femled-code-agent-github-app-id"
    github_app_private_key = "femled-code-agent-github-app-private-key"
    github_webhook_secret  = "github-org-webhook-secret"
    deploy_route_bundle    = "auth-broker-deploy-route-bundle"
    apns_coach_auth_key_p8 = "APNS_COACH_AUTH_KEY_P8"
    apns_coach_auth_key_id = "APNS_COACH_AUTH_KEY_ID"
    apple_team_id          = "APPLE_TEAM_ID"
  }
}

# ---------------------------------------------------------------------------
# Per-secret IAM bindings for the WIF federated identity
#
# Each secret grants secretAccessor only to workloads whose attestation
# token contains the expected container image digest. The operator cannot
# grant access to a different image -- only the WIF provider controls this.
# ---------------------------------------------------------------------------
locals {
  wif_principal = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.auth_broker.workload_identity_pool_id}/attribute.image_digest/${var.container_image_digest}"
  candidate_wif_principals = [
    for digest in var.candidate_image_digests :
    "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.auth_broker.workload_identity_pool_id}/attribute.image_digest/${digest}"
  ]

  secrets_needing_read = [
    local.secret_ids.google_client_id,
    local.secret_ids.google_client_secret,
    local.secret_ids.hmac_secret,
    local.secret_ids.broker_api_key,
    local.secret_ids.acme_account_key,
    local.secret_ids.github_app_id,
    local.secret_ids.github_app_private_key,
    local.secret_ids.github_webhook_secret,
    local.secret_ids.deploy_route_bundle,
    local.secret_ids.apns_coach_auth_key_p8,
    local.secret_ids.apns_coach_auth_key_id,
    local.secret_ids.apple_team_id,
  ]

  secrets_needing_write = [
    local.secret_ids.acme_account_key,
  ]

  candidate_secret_read_bindings = {
    for pair in setproduct(local.secrets_needing_read, local.candidate_wif_principals) :
    "${pair[0]}|${sha256(pair[1])}" => {
      secret_id = pair[0]
      member    = pair[1]
    }
  }

  candidate_secret_write_bindings = {
    for pair in setproduct(local.secrets_needing_write, local.candidate_wif_principals) :
    "${pair[0]}|${sha256(pair[1])}" => {
      secret_id = pair[0]
      member    = pair[1]
    }
  }
}

resource "google_secret_manager_secret_iam_member" "wif_read" {
  for_each  = toset(local.secrets_needing_read)
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = local.wif_principal
}

resource "google_secret_manager_secret_iam_member" "wif_write" {
  for_each  = toset(local.secrets_needing_write)
  secret_id = each.value
  role      = "roles/secretmanager.secretVersionAdder"
  member    = local.wif_principal
}

resource "google_secret_manager_secret_iam_member" "candidate_wif_read" {
  for_each  = local.candidate_secret_read_bindings
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = each.value.member
}

resource "google_secret_manager_secret_iam_member" "candidate_wif_write" {
  for_each  = local.candidate_secret_write_bindings
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretVersionAdder"
  member    = each.value.member
}

resource "google_project_iam_member" "wif_vertex_ai_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = local.wif_principal

  depends_on = [google_project_service.aiplatform]
}

resource "google_project_iam_member" "candidate_wif_vertex_ai_user" {
  for_each = toset(local.candidate_wif_principals)
  project  = var.project_id
  role     = "roles/aiplatform.user"
  member   = each.value

  depends_on = [google_project_service.aiplatform]
}

resource "google_project_iam_member" "wif_service_usage_consumer" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = local.wif_principal
}

resource "google_project_iam_member" "candidate_wif_service_usage_consumer" {
  for_each = toset(local.candidate_wif_principals)
  project  = var.project_id
  role     = "roles/serviceusage.serviceUsageConsumer"
  member   = each.value
}

resource "google_artifact_registry_repository_iam_member" "candidate_wif_artifact_reader" {
  for_each   = toset(local.candidate_wif_principals)
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.auth_broker.name
  role       = "roles/artifactregistry.reader"
  member     = each.value
}

# The successor activator script (scripts/activate-successor.mjs) calls the
# Artifact Registry Docker manifest API directly to capture an OCI evidence
# digest pinned to the candidate image, so the activator SA needs
# artifactregistry.repositories.downloadArtifacts on this repo. Its existing
# authBrokerSuccessorArtifactIam role only grants IAM management, not
# manifest reads, which is why the candidate-WIF reader bindings above are
# not sufficient -- those grant reader to the running candidate, not to the
# activator that fetches the manifest on the candidate's behalf.
resource "google_artifact_registry_repository_iam_member" "successor_activator_artifact_reader" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.auth_broker.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.successor_activation_service_account_email}"
}

# ---------------------------------------------------------------------------
# Confidential VM (workflow-managed)
#
# The auth-broker-tee VM is no longer created by Terraform. The
# build-and-attest workflow creates one ephemeral candidate VM per merge
# (named `auth-broker-tee-candidate-<digest12>`) and the successor
# activation flow promotes it; the static IP and Cloudflare A record that
# Terraform used to manage are likewise driven by the workflow's DNS
# update step. The `auth-broker-tee` compute SA, firewall rule, WIF pool,
# secrets, and IAM bindings remain Terraform-managed; only the ephemeral
# compute and DNS pointer moved out.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
resource "google_compute_firewall" "auth_broker_https" {
  name    = "auth-broker-tee-allow-https"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["auth-broker-tee"]

  depends_on = [google_project_service.compute]
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "oauth_url" {
  value = "https://oauth-tee.femled.ai"
}

output "artifact_registry_repo" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.auth_broker.repository_id}"
}

output "wif_pool" {
  value = google_iam_workload_identity_pool.auth_broker.workload_identity_pool_id
}

output "wif_provider" {
  value = google_iam_workload_identity_pool_provider.attestation_verifier.workload_identity_pool_provider_id
}

# ---------------------------------------------------------------------------
# Data access audit logs for WIF token exchanges
#
# Per Google's best practices: "enable data access logs for IAM APIs"
# to maintain a non-repudiable audit trail of all WIF token exchanges
# and service account impersonation events.
# ---------------------------------------------------------------------------
resource "google_project_iam_audit_config" "sts_audit" {
  project = var.project_id
  service = "sts.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

resource "google_project_iam_audit_config" "iam_audit" {
  project = var.project_id
  service = "iam.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

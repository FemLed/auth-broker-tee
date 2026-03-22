terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
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

resource "google_project_iam_member" "broker_datastore_viewer" {
  project = var.project_id
  role    = "roles/datastore.viewer"
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

  attribute_condition = join(" && ", [
    "assertion.swname == 'CONFIDENTIAL_SPACE'",
    "'STABLE' in assertion.submods.confidential_space.support_attributes",
    "assertion.submods.gce.project_id == '${var.project_id}'",
    "'${google_service_account.auth_broker_vm.email}' in assertion.google_service_accounts",
  ])

  depends_on = [google_project_service.sts]
}

# ---------------------------------------------------------------------------
# Secret Manager secrets (references to pre-existing secrets)
# ---------------------------------------------------------------------------
data "google_secret_manager_secret" "google_client_id" {
  secret_id  = "cloudflare-access-google-oauth-client-id"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "google_client_secret" {
  secret_id  = "cloudflare-access-google-oauth-client-secret"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "hmac_secret" {
  secret_id  = "auth-broker-hmac-secret"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "broker_api_key" {
  secret_id  = "broker-api-key"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "tls_cert" {
  secret_id  = "auth-broker-tls-cert"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "tls_key" {
  secret_id  = "auth-broker-tls-key"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "cloudflare_dns_token" {
  secret_id  = "auth-broker-cloudflare-dns-token"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "github_app_id" {
  secret_id  = "femled-code-agent-github-app-id"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "github_app_private_key" {
  secret_id  = "femled-code-agent-github-app-private-key"
  depends_on = [google_project_service.secret_manager]
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

  secrets_needing_read = [
    data.google_secret_manager_secret.google_client_id.secret_id,
    data.google_secret_manager_secret.google_client_secret.secret_id,
    data.google_secret_manager_secret.hmac_secret.secret_id,
    data.google_secret_manager_secret.broker_api_key.secret_id,
    data.google_secret_manager_secret.tls_cert.secret_id,
    data.google_secret_manager_secret.tls_key.secret_id,
    data.google_secret_manager_secret.cloudflare_dns_token.secret_id,
    data.google_secret_manager_secret.github_app_id.secret_id,
    data.google_secret_manager_secret.github_app_private_key.secret_id,
  ]

  secrets_needing_write = [
    data.google_secret_manager_secret.tls_cert.secret_id,
    data.google_secret_manager_secret.tls_key.secret_id,
  ]
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

# ---------------------------------------------------------------------------
# Confidential VM
#
# Metadata contains only non-sensitive configuration. All secrets are
# fetched at runtime via WIF from hardcoded Secret Manager resource names
# in the source code.
# ---------------------------------------------------------------------------
resource "google_compute_instance" "auth_broker" {
  name         = "auth-broker-tee"
  machine_type = var.machine_type
  zone         = var.zone

  confidential_instance_config {
    enable_confidential_compute = true
  }

  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  boot_disk {
    initialize_params {
      image = "projects/confidential-space-images/global/images/family/confidential-space"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.auth_broker_ip.address
    }
  }

  metadata = {
    "tee-image-reference"        = var.container_image
    "tee-restart-policy"         = "Always"
    "tee-env-GCP_PROJECT_ID"     = var.project_id
    "tee-env-GCP_PROJECT_NUMBER" = var.project_number
    "tee-env-REDIRECT_URI"       = "https://oauth-tee.femled.ai/callback"
    "tee-env-GOOGLE_SCOPES"      = "openid email profile https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/gmail.modify"
  }

  service_account {
    email  = google_service_account.auth_broker_vm.email
    scopes = ["cloud-platform"]
  }

  tags = ["auth-broker-tee"]

  depends_on = [
    google_project_service.compute,
    google_project_service.confidential_computing,
    google_iam_workload_identity_pool_provider.attestation_verifier,
  ]
}

# ---------------------------------------------------------------------------
# Static External IP Address
# ---------------------------------------------------------------------------
resource "google_compute_address" "auth_broker_ip" {
  name        = "auth-broker-tee-ip"
  region      = var.region
  description = "Static external IP for auth-broker TEE (oauth-tee.femled.ai)"

  depends_on = [google_project_service.compute]
}

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
# DNS: oauth-tee.femled.ai -> static IP (dns-only, not proxied)
# ---------------------------------------------------------------------------
resource "cloudflare_dns_record" "oauth_tee_femled_ai" {
  zone_id = var.cloudflare_zone_id
  name    = "oauth-tee"
  content = google_compute_address.auth_broker_ip.address
  type    = "A"
  ttl     = 300
  proxied = false
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "static_ip" {
  value = google_compute_address.auth_broker_ip.address
}

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

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

resource "google_project_iam_member" "broker_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
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

# ---------------------------------------------------------------------------
# References to pre-existing secrets in Secret Manager
#
# Secret values are populated via gcloud CLI (one-time setup), NOT via
# Terraform variables. This ensures no sensitive values appear in Terraform
# state, tfvars, or the public repository.
#
# Existing secrets:
#   broker-api-key
#   cloudflare-access-google-oauth-client-id
#   cloudflare-access-google-oauth-client-secret
#   auth-broker-hmac-secret
#   auth-broker-gcp-sa-key
#   auth-broker-tls-cert
#   auth-broker-tls-key
# ---------------------------------------------------------------------------
data "google_secret_manager_secret" "google_client_id" {
  secret_id = "cloudflare-access-google-oauth-client-id"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "google_client_secret" {
  secret_id = "cloudflare-access-google-oauth-client-secret"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "hmac_secret" {
  secret_id = "auth-broker-hmac-secret"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "broker_api_key" {
  secret_id = "broker-api-key"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "gcp_sa_key" {
  secret_id = "auth-broker-gcp-sa-key"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "tls_cert" {
  secret_id = "auth-broker-tls-cert"
  depends_on = [google_project_service.secret_manager]
}

data "google_secret_manager_secret" "tls_key" {
  secret_id = "auth-broker-tls-key"
  depends_on = [google_project_service.secret_manager]
}

# ---------------------------------------------------------------------------
# Cloud Build trigger
#
# The GitHub connection must be set up manually in the GCP Console first:
#   Console > Cloud Build > Triggers > Connect Repository > GitHub
# Once connected, create a trigger pointing to FemLed/auth-broker-tee,
# branch ^main$, using cloudbuild.yaml with substitutions:
#   _REGION=us-west1, _REPO=auth-broker, _IMAGE=auth-broker-tee
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Confidential VM running Confidential Space image
#
# On first deploy, build the container image first:
#   cd /path/to/auth-broker-tee
#   gcloud builds submit --config=cloudbuild.yaml \
#     --substitutions=_REGION=us-west1,_REPO=auth-broker,_IMAGE=auth-broker-tee \
#     --project=prod-femled-couple-router
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

  boot_disk {
    initialize_params {
      image = "projects/confidential-space-images/global/images/family/confidential-space"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  metadata = {
    "tee-image-reference" = var.container_image
    "tee-restart-policy"  = "Always"
    "tee-env-GOOGLE_CLIENT_ID"     = "secret:${data.google_secret_manager_secret.google_client_id.secret_id}"
    "tee-env-GOOGLE_CLIENT_SECRET" = "secret:${data.google_secret_manager_secret.google_client_secret.secret_id}"
    "tee-env-HMAC_SECRET"          = "secret:${data.google_secret_manager_secret.hmac_secret.secret_id}"
    "tee-env-BROKER_API_KEY"       = "secret:${data.google_secret_manager_secret.broker_api_key.secret_id}"
    "tee-env-GCP_SA_KEY"           = "secret:${data.google_secret_manager_secret.gcp_sa_key.secret_id}"
    "tee-env-GCP_PROJECT_ID"       = var.project_id
    "tee-env-REDIRECT_URI"         = "https://oauth-tee.femled.ai/callback"
    "tee-env-GOOGLE_SCOPES"        = "openid email profile https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/gmail.modify"
    "tee-env-TLS_CERT_SECRET"      = "${data.google_secret_manager_secret.tls_cert.id}/versions/latest"
    "tee-env-TLS_KEY_SECRET"       = "${data.google_secret_manager_secret.tls_key.id}/versions/latest"
  }

  service_account {
    email  = google_service_account.auth_broker_vm.email
    scopes = ["cloud-platform"]
  }

  tags = ["auth-broker-tee"]

  depends_on = [
    google_project_service.compute,
    google_project_service.confidential_computing,
  ]
}

# ---------------------------------------------------------------------------
# Firewall: allow HTTPS (443) and health check (8080) traffic
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

resource "google_compute_firewall" "auth_broker_health" {
  name    = "auth-broker-tee-allow-health"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
  target_tags   = ["auth-broker-tee"]

  depends_on = [google_project_service.compute]
}

# ---------------------------------------------------------------------------
# TCP Passthrough Network Load Balancer
# ---------------------------------------------------------------------------
resource "google_compute_instance_group" "auth_broker" {
  name = "auth-broker-tee-group"
  zone = var.zone

  instances = [google_compute_instance.auth_broker.id]

  named_port {
    name = "https"
    port = 443
  }
}

resource "google_compute_region_health_check" "auth_broker" {
  name               = "auth-broker-tee-health"
  region             = var.region
  check_interval_sec = 10
  timeout_sec        = 5

  http_health_check {
    port         = 8080
    request_path = "/health"
  }

  depends_on = [google_project_service.compute]
}

resource "google_compute_region_backend_service" "auth_broker" {
  name                  = "auth-broker-tee-backend"
  region                = var.region
  protocol              = "TCP"
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_region_health_check.auth_broker.id]

  backend {
    group          = google_compute_instance_group.auth_broker.id
    balancing_mode = "CONNECTION"
  }
}

resource "google_compute_forwarding_rule" "auth_broker" {
  name                  = "auth-broker-tee-forwarding"
  region                = var.region
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  ip_protocol           = "TCP"
  backend_service       = google_compute_region_backend_service.auth_broker.id
}

# ---------------------------------------------------------------------------
# DNS: oauth-tee.femled.ai -> NLB IP
# ---------------------------------------------------------------------------
resource "cloudflare_dns_record" "oauth_tee_femled_ai" {
  zone_id = var.cloudflare_zone_id
  name    = "oauth-tee"
  content = google_compute_forwarding_rule.auth_broker.ip_address
  type    = "A"
  ttl     = 300
  proxied = false
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "nlb_ip" {
  value = google_compute_forwarding_rule.auth_broker.ip_address
}

output "oauth_url" {
  value = "https://oauth-tee.femled.ai"
}

output "artifact_registry_repo" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.auth_broker.repository_id}"
}

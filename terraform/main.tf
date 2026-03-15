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
# Artifact Registry
# ---------------------------------------------------------------------------
resource "google_artifact_registry_repository" "auth_broker" {
  location      = var.region
  repository_id = "auth-broker"
  format        = "DOCKER"
  description   = "Auth broker TEE container images"
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

# ---------------------------------------------------------------------------
# Secrets (references only -- values must be created manually or via CLI)
# ---------------------------------------------------------------------------
resource "google_secret_manager_secret" "google_client_id" {
  secret_id = "auth-broker-google-client-id"
  replication { auto {} }
}

resource "google_secret_manager_secret" "google_client_secret" {
  secret_id = "auth-broker-google-client-secret"
  replication { auto {} }
}

resource "google_secret_manager_secret" "hmac_secret" {
  secret_id = "auth-broker-hmac-secret"
  replication { auto {} }
}

resource "google_secret_manager_secret" "broker_api_key" {
  secret_id = "auth-broker-api-key"
  replication { auto {} }
}

resource "google_secret_manager_secret" "gcp_sa_key" {
  secret_id = "auth-broker-gcp-sa-key"
  replication { auto {} }
}

resource "google_secret_manager_secret" "tls_cert" {
  secret_id = "auth-broker-tls-cert"
  replication { auto {} }
}

resource "google_secret_manager_secret" "tls_key" {
  secret_id = "auth-broker-tls-key"
  replication { auto {} }
}

# ---------------------------------------------------------------------------
# Confidential VM running Confidential Space image
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
    "tee-env-GOOGLE_CLIENT_ID"     = "secret:${google_secret_manager_secret.google_client_id.secret_id}"
    "tee-env-GOOGLE_CLIENT_SECRET" = "secret:${google_secret_manager_secret.google_client_secret.secret_id}"
    "tee-env-HMAC_SECRET"          = "secret:${google_secret_manager_secret.hmac_secret.secret_id}"
    "tee-env-BROKER_API_KEY"       = "secret:${google_secret_manager_secret.broker_api_key.secret_id}"
    "tee-env-GCP_SA_KEY"           = "secret:${google_secret_manager_secret.gcp_sa_key.secret_id}"
    "tee-env-GCP_PROJECT_ID"       = var.project_id
    "tee-env-REDIRECT_URI"         = "https://oauth.femled.ai/callback"
    "tee-env-GOOGLE_SCOPES"        = "openid email profile https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/gmail.modify"
    "tee-env-TLS_CERT_SECRET"      = "${google_secret_manager_secret.tls_cert.id}/versions/latest"
    "tee-env-TLS_KEY_SECRET"       = "${google_secret_manager_secret.tls_key.id}/versions/latest"
  }

  service_account {
    email  = google_service_account.auth_broker_vm.email
    scopes = ["cloud-platform"]
  }

  tags = ["auth-broker-tee"]
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

resource "google_compute_health_check" "auth_broker" {
  name               = "auth-broker-tee-health"
  check_interval_sec = 10
  timeout_sec        = 5

  http_health_check {
    port = 8080
    request_path = "/health"
  }
}

resource "google_compute_region_backend_service" "auth_broker" {
  name                  = "auth-broker-tee-backend"
  region                = var.region
  protocol              = "TCP"
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_health_check.auth_broker.id]

  backend {
    group = google_compute_instance_group.auth_broker.id
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
# DNS: oauth.femled.ai -> NLB IP
# ---------------------------------------------------------------------------
resource "cloudflare_dns_record" "oauth_femled_ai" {
  zone_id = var.cloudflare_zone_id
  name    = "oauth"
  content = google_compute_forwarding_rule.auth_broker.ip_address
  type    = "A"
  ttl     = 300
  proxied = false
}

output "nlb_ip" {
  value = google_compute_forwarding_rule.auth_broker.ip_address
}

output "oauth_url" {
  value = "https://oauth.femled.ai"
}

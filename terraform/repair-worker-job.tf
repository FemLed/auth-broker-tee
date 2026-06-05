# ---------------------------------------------------------------------------
# Auth Broker TEE repair worker
#
# This job is intentionally an untrusted candidate builder. It may create
# source branches and PRs, but it does not receive governance keys, activation
# authority, KMS signer rights, WIF policy rights, route-registry mutation
# rights, or Cloud Run/Compute traffic update permissions.
# ---------------------------------------------------------------------------

resource "google_project_service" "cloud_run" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

variable "enable_repair_worker" {
  description = "Provision the untrusted auth-broker repair-worker Cloud Run Job."
  type        = bool
  default     = true
}

variable "repair_worker_image_digest" {
  description = "Pre-resolved repair-worker image digest. Set by CI or leave empty to resolve repair_worker_image:repair_worker_image_tag locally."
  type        = string
  default     = ""
  validation {
    condition     = var.repair_worker_image_digest == "" || can(regex("^sha256:[a-f0-9]{64}$", var.repair_worker_image_digest))
    error_message = "repair_worker_image_digest must be empty or a sha256 digest."
  }
}

variable "repair_worker_image" {
  description = "Repair-worker image repository path without digest."
  type        = string
  default     = "us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee-repair-worker"
}

variable "repair_worker_image_tag" {
  description = "Repair-worker image tag to resolve when repair_worker_image_digest is empty."
  type        = string
  default     = "latest"
}

data "external" "repair_worker_image_digest" {
  count = var.enable_repair_worker && var.repair_worker_image_digest == "" ? 1 : 0
  program = ["bash", "-c", <<-EOF
    DIGEST=$(gcloud artifacts docker images describe ${var.repair_worker_image}:${var.repair_worker_image_tag} --format='value(image_summary.digest)' 2>/dev/null)
    echo "{\"digest\": \"$DIGEST\"}"
  EOF
  ]
}

locals {
  repair_worker_image_digest = var.repair_worker_image_digest != "" ? var.repair_worker_image_digest : try(data.external.repair_worker_image_digest[0].result.digest, "")
  repair_worker_enabled      = var.enable_repair_worker && local.repair_worker_image_digest != ""
}

resource "google_service_account" "auth_broker_repair_worker" {
  count        = local.repair_worker_enabled ? 1 : 0
  account_id   = "auth-broker-repair-worker"
  display_name = "Auth Broker TEE Repair Worker"
  description  = "Untrusted mini-swe-agent candidate builder for auth-broker-tee repair proposals"
}

locals {
  repair_worker_roles = local.repair_worker_enabled ? toset([
    "roles/aiplatform.user",
    "roles/artifactregistry.reader",
    "roles/cloudbuild.builds.viewer",
    "roles/logging.logWriter",
  ]) : toset([])
}

resource "google_project_iam_member" "auth_broker_repair_worker_roles" {
  for_each = local.repair_worker_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.auth_broker_repair_worker[0].email}"
}

resource "google_cloud_run_v2_job" "auth_broker_repair_worker" {
  count               = local.repair_worker_enabled ? 1 : 0
  name                = "auth-broker-tee-repair-worker"
  location            = var.region
  project             = var.project_id
  deletion_protection = false

  depends_on = [
    google_project_service.cloud_run,
    google_project_iam_member.auth_broker_repair_worker_roles,
  ]

  template {
    task_count = 1

    template {
      service_account = google_service_account.auth_broker_repair_worker[0].email
      timeout         = "5400s"

      containers {
        image = "${var.repair_worker_image}@${local.repair_worker_image_digest}"

        resources {
          limits = {
            cpu    = "2"
            memory = "4Gi"
          }
        }

        env {
          name  = "GCP_PROJECT_ID"
          value = var.project_id
        }

        env {
          name  = "VERTEXAI_PROJECT"
          value = var.project_id
        }

        env {
          name  = "VERTEXAI_LOCATION"
          value = "global"
        }

        env {
          name  = "GITHUB_REPO_OWNER"
          value = split("/", var.gh_repo)[0]
        }

        env {
          name  = "GITHUB_REPO_NAME"
          value = split("/", var.gh_repo)[1]
        }

        # TEE_REPAIR_JOB_ID, TEE_REPAIR_PROPOSAL_DIGEST, TEE_REPAIR_PROMPT,
        # TEE_REPAIR_CALLBACK_URL, and TEE_REPAIR_CALLBACK_TOKEN are per-run
        # overrides supplied by the orchestrator after it verifies an active
        # TEE signed repair proposal. GitHub write tokens are intentionally not
        # passed through Cloud Run job environment overrides.
      }
    }
  }
}

resource "google_project_iam_custom_role" "auth_broker_repair_launcher" {
  count       = local.repair_worker_enabled ? 1 : 0
  role_id     = "authBrokerRepairLauncher"
  title       = "Auth Broker Repair Launcher"
  description = "Minimal permissions for the active TEE to run and inspect the pre-provisioned repair-worker job"
  permissions = [
    "run.executions.get",
    "run.jobs.get",
    "run.jobs.run",
    "run.jobs.runWithOverrides",
    "run.operations.get",
  ]
}

resource "google_project_iam_member" "auth_broker_wif_repair_launcher" {
  count   = local.repair_worker_enabled ? 1 : 0
  project = var.project_id
  role    = google_project_iam_custom_role.auth_broker_repair_launcher[0].id
  member  = local.wif_principal
}

output "auth_broker_repair_worker_job_name" {
  description = "Cloud Run Job name for the untrusted auth-broker repair worker"
  value       = local.repair_worker_enabled ? google_cloud_run_v2_job.auth_broker_repair_worker[0].name : "(not deployed -- no repair-worker image found)"
}

output "auth_broker_repair_worker_image_digest" {
  description = "Resolved repair-worker image digest used by the Cloud Run Job"
  value       = local.repair_worker_image_digest
}

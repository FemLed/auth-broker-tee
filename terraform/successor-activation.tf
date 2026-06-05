# ---------------------------------------------------------------------------
# Successor activation automation
#
# `auth-broker-activator` may prepare resource-level candidate IAM bindings and
# create inactive candidate VMs, but it must not receive raw project IAM
# mutation authority. Project-level candidate grants are delegated to this
# constrained Cloud Run Job, whose runtime code hardcodes the only accepted
# roles and derives the candidate WIF principal from a sha256 digest.
# ---------------------------------------------------------------------------

variable "successor_activation_service_account_email" {
  description = "Existing service account used by build-and-attest successor activation. It may invoke the constrained project-role reconciler but must not hold resourcemanager.projects.setIamPolicy directly."
  type        = string
  default     = "auth-broker-activator@prod-femled-couple-router.iam.gserviceaccount.com"
}

resource "google_service_account" "candidate_project_role_reconciler" {
  account_id   = "candidate-role-reconciler"
  display_name = "Auth Broker Candidate Project Role Reconciler"
  description  = "Constrained job that grants/revokes only allowed project roles for auth-broker successor candidate WIF principals"
}

resource "google_project_iam_custom_role" "candidate_project_role_reconciler" {
  role_id     = "authBrokerCandidateRoleReconciler"
  title       = "Auth Broker Candidate Role Reconciler"
  description = "Can edit project IAM only for the hardcoded candidate WIF project-role reconciler job"
  permissions = [
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.setIamPolicy",
  ]
}

resource "google_project_iam_member" "candidate_project_role_reconciler" {
  project = var.project_id
  role    = google_project_iam_custom_role.candidate_project_role_reconciler.id
  member  = "serviceAccount:${google_service_account.candidate_project_role_reconciler.email}"
}

resource "google_cloud_run_v2_job" "candidate_project_role_reconciler" {
  name                = "auth-broker-candidate-role-reconciler"
  location            = var.region
  project             = var.project_id
  deletion_protection = false

  depends_on = [
    google_project_service.cloud_run,
    google_project_iam_member.candidate_project_role_reconciler,
  ]

  template {
    task_count = 1

    template {
      service_account = google_service_account.candidate_project_role_reconciler.email
      timeout         = "600s"

      containers {
        image   = "gcr.io/google.com/cloudsdktool/google-cloud-cli:slim"
        command = ["/bin/bash", "-ceu"]
        args    = [file("${path.module}/../scripts/reconcile-candidate-project-roles.sh")]

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }

        env {
          name  = "PROJECT_NUMBER"
          value = var.project_number
        }

        env {
          name  = "WIF_POOL_ID"
          value = google_iam_workload_identity_pool.auth_broker.workload_identity_pool_id
        }
      }
    }
  }
}

resource "google_project_iam_custom_role" "candidate_project_role_reconciler_invoker" {
  role_id     = "authBrokerCandidateRoleReconcilerInvoker"
  title       = "Auth Broker Candidate Role Reconciler Invoker"
  description = "Can invoke the constrained auth-broker candidate project-role reconciler job"
  permissions = [
    "run.executions.get",
    "run.jobs.get",
    "run.jobs.run",
    "run.jobs.runWithOverrides",
    "run.operations.get",
  ]
}

resource "google_project_iam_member" "successor_activator_reconciler_invoker" {
  project = var.project_id
  role    = google_project_iam_custom_role.candidate_project_role_reconciler_invoker.id
  member  = "serviceAccount:${var.successor_activation_service_account_email}"
}

output "candidate_project_role_reconciler_job_name" {
  description = "Cloud Run Job that grants/revokes only candidate aiplatform.user and serviceusage.serviceUsageConsumer project bindings"
  value       = google_cloud_run_v2_job.candidate_project_role_reconciler.name
}

output "candidate_project_role_reconciler_service_account" {
  description = "Service account that owns the constrained project IAM mutation authority"
  value       = google_service_account.candidate_project_role_reconciler.email
}

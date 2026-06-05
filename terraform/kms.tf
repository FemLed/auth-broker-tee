# ---------------------------------------------------------------------------
# Cloud KMS asymmetric signing key for Confidential Space's signed-image flow
#
# This is the most trust-load-bearing resource in the whole stack: any
# principal that can `cloudkms.signer` against this crypto-key version can
# produce a Confidential Space-acceptable image signature, which the WIF
# attribute_condition then accepts as proof that the running container is
# the expected one. The IAM grant below is intentionally narrow:
#
#   - role         = roles/cloudkms.signerVerifier
#   - member       = the WIF-federated gh_actions_publisher SA
#   - scope        = this single crypto_key (NOT keyring, NOT project)
#
# Anything that broadens this -- a user member, a service account at the
# project or keyring level, a different key, an additional role -- shows
# up as a Terraform diff AND is recorded in Cloud Audit Logs. Stream
# those logs to an external sink the FemLed operator does not control if
# you want belt-and-suspenders defense against an adversarial future-self.
#
# The keyless Sigstore signature produced in the same workflow stays as
# the public-transparency layer (verified by the standalone verifier
# binary against Rekor); this KMS key exists ONLY to give Confidential
# Space's launcher and the WIF condition something to mechanically check.
# ---------------------------------------------------------------------------

resource "google_project_service" "cloudkms" {
  service            = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

resource "google_kms_key_ring" "image_signing" {
  name     = var.cosign_kms_keyring_id
  location = var.region

  depends_on = [google_project_service.cloudkms]
}

resource "google_kms_crypto_key" "image_signer" {
  name     = var.cosign_kms_key_id
  key_ring = google_kms_key_ring.image_signing.id
  purpose  = "ASYMMETRIC_SIGN"

  # Manual rotation only: each rotation is a deliberate, reviewed event.
  # See SUPPLY_CHAIN_BOOTSTRAP.md "KMS key rotation procedure" for the
  # dual-fingerprint-acceptance window we run during the swap.
  version_template {
    algorithm        = var.cosign_kms_key_algorithm
    protection_level = "SOFTWARE"
  }

  # Destroying this key would brick image signing for every subsequent
  # build AND would invalidate every signature already in flight. Force
  # the operator to remove `prevent_destroy` deliberately if they really
  # mean it.
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "gha_signer" {
  crypto_key_id = google_kms_crypto_key.image_signer.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.gh_actions_publisher.email}"
}

resource "google_kms_crypto_key_iam_member" "gha_key_viewer" {
  crypto_key_id = google_kms_crypto_key.image_signer.id
  role          = "roles/cloudkms.viewer"
  member        = "serviceAccount:${google_service_account.gh_actions_publisher.email}"
}

# Pull the live public key for the primary version so we can surface
# both the PEM (for external verifiers) and the hex-SHA256 fingerprint
# (the value Confidential Space exposes as `image_signatures[].key_id`).
data "google_kms_crypto_key_version" "image_signer_v1" {
  crypto_key = google_kms_crypto_key.image_signer.id
}

locals {
  # KMS resource URI WITHOUT a `/cryptoKeyVersions/N` suffix so cosign
  # uses whatever KMS key version is currently primary. Rotation is
  # therefore "promote a new version to primary" without touching the
  # GHA workflow file.
  image_signer_kms_key_uri = "gcpkms://${google_kms_crypto_key.image_signer.id}"

  # CEL list of accepted "<algorithm>:<fingerprint>" strings. When
  # `expected_image_signer_fingerprint_old` is empty, this is a single-
  # element list; during a rotation window it has two. Built here so
  # main.tf's WIF condition is just one CEL `.exists(...)` call rather
  # than fragile string interpolation.
  accepted_image_signer_fingerprints = compact([
    "${var.cosign_kms_attestation_signature_algorithm}:${var.expected_image_signer_fingerprint}",
    var.expected_image_signer_fingerprint_old == "" ? "" : "${var.cosign_kms_attestation_signature_algorithm}:${var.expected_image_signer_fingerprint_old}",
  ])
  accepted_image_signer_celset = "[${join(", ", [for fp in local.accepted_image_signer_fingerprints : "'${fp}'"])}]"
}

output "image_signer_kms_key_uri" {
  description = "KMS resource URI passed to `cosign sign --key gcpkms://...` in the build-and-attest workflow"
  value       = local.image_signer_kms_key_uri
}

output "image_signer_fingerprint" {
  description = "Hex SHA-256 fingerprint currently pinned in WIF. Compute the live KMS public-key fingerprint outside Terraform with `cosign public-key --key ... | openssl pkey -pubin -outform DER | openssl dgst -sha256`, then paste it into `expected_image_signer_fingerprint`."
  value       = var.expected_image_signer_fingerprint
}

output "image_signer_public_key_pem" {
  description = "PEM-encoded public key for the Cosign signing key. Distribute alongside release notes so external verifiers can independently confirm the key_id."
  value       = data.google_kms_crypto_key_version.image_signer_v1.public_key[0].pem
}

# ---------------------------------------------------------------------------
# Audit logging for the load-bearing KMS surface
#
# Two layers:
#
#   1. `google_project_iam_audit_config.kms_audit` enables ADMIN_READ +
#      DATA_READ + DATA_WRITE for cloudkms.googleapis.com. Every IAM
#      mutation, every signing operation, and every key administration
#      call is recorded in Cloud Audit Logs in this project.
#
#   2. `google_logging_project_sink.kms_audit_export` (only when
#      `var.kms_audit_log_sink_destination` is set) pipes those logs
#      to an EXTERNAL destination -- ideally a bucket / pub-sub topic
#      / BigQuery dataset owned by a different identity than this
#      project's owners. Without this, an operator who can edit Cloud
#      Logging in this project can also delete the audit trail.
#
# The filter targets only events that matter for trust drift: IAM
# changes on the signing key, and signing operations themselves
# (so external watchers can detect "someone signed a payload outside
# of the GHA workflow").
# ---------------------------------------------------------------------------
resource "google_project_iam_audit_config" "kms_audit" {
  project = var.project_id
  service = "cloudkms.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

resource "google_logging_project_sink" "kms_audit_export" {
  count = var.kms_audit_log_sink_destination == "" ? 0 : 1

  name        = "auth-broker-kms-audit-export"
  destination = var.kms_audit_log_sink_destination

  filter = join(" OR ", [
    "(protoPayload.serviceName=\"cloudkms.googleapis.com\" AND protoPayload.resourceName:\"${google_kms_crypto_key.image_signer.id}\")",
    "(protoPayload.serviceName=\"iam.googleapis.com\" AND protoPayload.request.policy.bindings.role:\"cloudkms.signer\")",
  ])

  unique_writer_identity = true
}

output "kms_audit_sink_writer_identity" {
  description = "Writer identity for the KMS audit-log sink. Grant this principal write access (e.g. roles/storage.objectCreator) on the external destination so the sink can deliver. Empty when no sink is configured."
  value       = var.kms_audit_log_sink_destination == "" ? "" : google_logging_project_sink.kms_audit_export[0].writer_identity
}

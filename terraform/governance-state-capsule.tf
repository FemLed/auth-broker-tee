# ============================================================================
# Governance state persistence: KMS-held signing key + GCS capsule bucket.
#
# Auth-broker-tee's governance state (lineage, epoch, route policy) has
# historically been process-memory only. The renewer's
# `compute.instances.reset` at the end of a successful ACME run wiped that
# state, and host-maintenance restarts (live-migration failures, hardware
# events) do the same out of operator control. The recovery escape hatch was
# `GENESIS_RECOVERY_MODE`, which lets the running TEE re-self-attest as the
# genesis reviewer. That works under duress but cannot be the steady state:
# every unplanned restart still surfaces as governance loss, and tenant route
# admissions (`transferredState.routePolicy`) are not recoverable from it.
#
# This file provisions the two resources that let the broker survive a VM
# reset without operator intervention:
#
#   1. `governance_signer` (ECDSA P-256 in Cloud KMS). The governance
#      signing key moves out of process memory into Cloud KMS, gated by the
#      same WIF principal pattern (`attribute.image_digest`) we already use
#      for Secret Manager and the renewer signer. The same image running on
#      a fresh VM can call `asymmetricSign` against this exact key version;
#      no other principal can. The KMS public key plus key-version resource
#      name end up as the governance lineage tail's signing identity, so the
#      lineage tail key still validates after a restart.
#
#   2. `governance_state_capsules` GCS bucket. After every state mutation,
#      the running TEE seals (lineage, epoch, transferredState.routePolicy,
#      latestPreapproval/Successor/Retirement certs) into a capsule whose
#      AAD is bound to the running imageDigest + KMS key version + lineage
#      digest + epoch + transferredState digest. On cold start the same
#      image attests via WIF, reads the capsule, verifies the AAD, and
#      restores `status=active` with the prior lineage.
#
# The KMS audit-log sink defined in `kms.tf` already covers this keyring's
# parent project; signing events on this key surface in the same audit
# stream so an external watcher can detect "someone signed a governance
# payload outside of the running TEE."
# ============================================================================

resource "google_kms_key_ring" "governance" {
  name       = "auth-broker-governance"
  location   = var.region
  depends_on = [google_project_service.cloudkms]
}

resource "google_kms_crypto_key" "governance_signer" {
  name     = "governance-signer"
  key_ring = google_kms_key_ring.governance.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  # Destroying this key breaks every signature in the on-GCS capsule
  # lineage tail and bricks restart recovery. Rotation is a deliberate
  # event (promote a new version to primary; bridge through one capsule
  # write under the new version), not a Terraform destroy.
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "governance_signer_wif" {
  crypto_key_id = google_kms_crypto_key.governance_signer.id
  role          = "roles/cloudkms.signerVerifier"
  member        = local.wif_principal
}

resource "google_kms_crypto_key_iam_member" "governance_signer_viewer" {
  crypto_key_id = google_kms_crypto_key.governance_signer.id
  role          = "roles/cloudkms.viewer"
  member        = local.wif_principal
}

resource "google_kms_crypto_key_iam_member" "governance_signer_candidates" {
  for_each      = toset(local.candidate_wif_principals)
  crypto_key_id = google_kms_crypto_key.governance_signer.id
  role          = "roles/cloudkms.signerVerifier"
  member        = each.value
}

resource "google_kms_crypto_key_iam_member" "governance_signer_viewer_candidates" {
  for_each      = toset(local.candidate_wif_principals)
  crypto_key_id = google_kms_crypto_key.governance_signer.id
  role          = "roles/cloudkms.viewer"
  member        = each.value
}

# Read primary version so we can surface the resource path (used as the
# `GOVERNANCE_KMS_SIGNER_KEY_VERSION` env var baked into VM metadata).
data "google_kms_crypto_key_version" "governance_signer_v1" {
  crypto_key = google_kms_crypto_key.governance_signer.id
}

# ----------------------------------------------------------------------------
# GCS bucket: state capsules.
#
# Objects are encrypted application-side (AES-256-GCM with a key wrapped by
# the governance KMS key via `asymmetricSign`-derived shared secret; see
# src/state-capsule.js). The bucket is untrusted storage; integrity comes
# from the capsule's own AAD + signature, not bucket-level ACLs. We still
# lock the bucket down because there is no reason for any other principal
# to read or write capsules.
# ----------------------------------------------------------------------------
resource "google_storage_bucket" "governance_state_capsules" {
  name                        = "${var.project_id}-auth-broker-tee-governance-capsules"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # Keep ~90 days of capsule history so a botched restore can be rolled
  # back via a manual operator action (write an older capsule digest to
  # `capsules/latest-pointer.json`). Older versions tombstone after that.
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      num_newer_versions = 30
      with_state         = "ARCHIVED"
    }
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age        = 365
      with_state = "ANY"
    }
  }
}

resource "google_storage_bucket_iam_member" "governance_capsules_reader" {
  bucket = google_storage_bucket.governance_state_capsules.name
  role   = "roles/storage.objectViewer"
  member = local.wif_principal
}

resource "google_storage_bucket_iam_member" "governance_capsules_writer" {
  bucket = google_storage_bucket.governance_state_capsules.name
  role   = "roles/storage.objectCreator"
  member = local.wif_principal
}

# The "latest-pointer.json" object is updated in place after every successful
# capsule write. Granting objectAdmin on this single object lets the WIF
# principal overwrite the pointer without granting bucket-wide admin.
resource "google_storage_bucket_iam_member" "governance_capsules_pointer_admin" {
  bucket = google_storage_bucket.governance_state_capsules.name
  role   = "roles/storage.objectAdmin"
  member = local.wif_principal

  condition {
    title       = "Latest pointer object only"
    description = "Restrict objectAdmin to capsules/latest-pointer.json so capsule history is immutable except via versioning."
    expression  = "resource.name.endsWith(\"/objects/capsules/latest-pointer.json\")"
  }
}

resource "google_storage_bucket_iam_member" "governance_capsules_reader_candidates" {
  for_each = toset(local.candidate_wif_principals)
  bucket   = google_storage_bucket.governance_state_capsules.name
  role     = "roles/storage.objectViewer"
  member   = each.value
}

resource "google_storage_bucket_iam_member" "governance_capsules_writer_candidates" {
  for_each = toset(local.candidate_wif_principals)
  bucket   = google_storage_bucket.governance_state_capsules.name
  role     = "roles/storage.objectCreator"
  member   = each.value
}

resource "google_storage_bucket_iam_member" "governance_capsules_pointer_admin_candidates" {
  for_each = toset(local.candidate_wif_principals)
  bucket   = google_storage_bucket.governance_state_capsules.name
  role     = "roles/storage.objectAdmin"
  member   = each.value

  condition {
    title       = "Latest pointer object only (candidate)"
    description = "Restrict objectAdmin to capsules/latest-pointer.json for the candidate image digest."
    expression  = "resource.name.endsWith(\"/objects/capsules/latest-pointer.json\")"
  }
}

output "governance_signer_key_version" {
  description = "KMS key-version resource path for the governance signing key. Wired into VM metadata as tee-env-GOVERNANCE_KMS_SIGNER_KEY_VERSION."
  value       = "${google_kms_crypto_key.governance_signer.id}/cryptoKeyVersions/1"
}

output "governance_signer_public_key_pem" {
  description = "PEM-encoded public key for the governance signing key. Compare against the lineage tail's signingKeyId fingerprint when verifying a capsule restore."
  value       = data.google_kms_crypto_key_version.governance_signer_v1.public_key[0].pem
}

output "governance_state_capsule_bucket" {
  description = "GCS bucket where the running TEE seals governance state capsules. Wired into VM metadata as tee-env-CAPSULE_BUCKET."
  value       = google_storage_bucket.governance_state_capsules.name
}

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

  # Versioning is required so the in-place writes (latest-pointer, mint-log)
  # create new object versions rather than replacing a retention-locked one.
  versioning {
    enabled = true
  }

  # ANTI-ROLLBACK: a LOCKED retention policy is what makes "restore the highest
  # authentic capsule serial" rollback-resistant against a hostile bucket owner
  # -- once locked, not even a project owner can delete or overwrite an object
  # before it meets the retention period, so the true-head capsule cannot be
  # removed to force a downgrade to an older still-present capsule. The broker
  # re-seals a fresh head at least daily (governanceCapsuleHeartbeatIfDue), so
  # 35 days is ample headroom over any heartbeat stall or reboot gap.
  #
  # STAGED LOCK (is_locked is IRREVERSIBLE once true): this ships is_locked=false
  # so the retention window can be applied and a real cold-boot restore verified
  # first. Flip to `is_locked = true` in a follow-up apply once verified; the
  # anti-rollback guarantee is only owner-resistant after the lock is set.
  retention_policy {
    retention_period = 3024000 # 35 days, in seconds
    is_locked        = false
  }

  # Bound the bucket (and thus the cold-start scan) at ~45 days. Retention
  # (above) prevents deletion before 35 days; this deletes capsules shortly
  # after, so the bucket holds ~35-45 days of daily-heartbeat capsules -- a few
  # dozen objects, well under the MAX_CAPSULES_SCANNED cap in governance-state.js.
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
      age        = 45
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

# TLS is ephemeral: the leaf key+cert are minted fresh in enclave memory on
# every boot and never sealed, so there is NO `tls/oauth-tee.tls-capsule.v1.json`
# object and no objectAdmin grant for it. The only non-governance object this
# bucket now holds on the TLS path is the non-secret mint ledger
# (`tls/mint-log.v1.json`, timestamps only). It is overwritten in place on every
# mint, so -- like the latest-pointer -- grant objectAdmin restricted to exactly
# that object. It contains no key material; tampering only affects availability.
resource "google_storage_bucket_iam_member" "tls_mint_log_object_admin" {
  bucket = google_storage_bucket.governance_state_capsules.name
  role   = "roles/storage.objectAdmin"
  member = local.wif_principal

  condition {
    title       = "TLS mint ledger object only"
    description = "Restrict objectAdmin to the non-secret TLS mint ledger so it can be updated in place."
    expression  = "resource.name.endsWith(\"/objects/tls/mint-log.v1.json\")"
  }
}

resource "google_storage_bucket_iam_member" "tls_mint_log_object_admin_candidates" {
  for_each = toset(local.candidate_wif_principals)
  bucket   = google_storage_bucket.governance_state_capsules.name
  role     = "roles/storage.objectAdmin"
  member   = each.value

  condition {
    title       = "TLS mint ledger object only (candidate)"
    description = "Restrict objectAdmin to the non-secret TLS mint ledger for the candidate image digest."
    expression  = "resource.name.endsWith(\"/objects/tls/mint-log.v1.json\")"
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

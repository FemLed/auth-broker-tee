# ============================================================================
# Retired governance KMS key, and the bucket that now holds the TLS mint ledger.
#
# The broker signs governance with a key generated in enclave memory; no
# principal is granted the KMS governance signer, and no governance state is
# written to Cloud Storage. Earlier images used both: anyone administering the
# project could self-grant `cloudkms.signerVerifier` on the key and sign as the
# broker, and the capsules' data key was derivable from fields stored in the
# capsule. Version 1 of the key is disabled and scheduled for destruction
# outside Terraform.
#
# KMS keys cannot be deleted, so the key ring and key stay declared with no
# IAM bindings. The bucket stays: it holds the non-secret TLS mint ledger and
# the historical capsules its locked retention policy still keeps.
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

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket" "governance_state_capsules" {
  name                        = "${var.project_id}-auth-broker-tee-governance-capsules"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Versioning is required so the in-place mint-ledger writes create new object
  # versions rather than replacing a retention-locked one.
  versioning {
    enabled = true
  }

  # Locked in production since 2026-07-03; the lock is irreversible.
  retention_policy {
    retention_period = 3024000 # 35 days, in seconds
    is_locked        = true
  }

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

# TLS is ephemeral: the leaf key+cert are minted fresh in enclave memory on
# every boot and never sealed. The only object the broker writes here is the
# non-secret mint ledger (`tls/mint-log.v1.json`, timestamps only), overwritten
# in place on every mint, so objectAdmin is restricted to exactly that object.
# It contains no key material; tampering only affects availability.
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

output "tls_mint_log_bucket" {
  description = "GCS bucket holding the non-secret TLS mint ledger (tls/mint-log.v1.json)."
  value       = google_storage_bucket.governance_state_capsules.name
}

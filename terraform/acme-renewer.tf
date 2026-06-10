# ============================================================================
# In-TEE ACME renewer (DNS-01 via authoritative-dns-tee) + sealed TLS capsule.
#
# This file provisions:
#   - ECDSA P-256 governance signer key in Cloud KMS, image-baked-fingerprinted
#     into authoritative-dns-tee's EXTERNAL_TEE_RENEWERS.
#   - `auth-broker-tee-acme-account-key` Secret Manager secret for the
#     persistent ACME account key.
#   - The `tls-sealing` ENCRYPT_DECRYPT KMS key that wraps the DEK of the
#     sealed TLS capsule (src/tls-capsule.js). TLS private keys are NEVER
#     stored in Secret Manager: the leaf key+cert live in enclave memory and
#     the only at-rest form is the AES-256-GCM capsule in the governance
#     state-capsule bucket (tls/ object). Decrypt IAM on the sealing key is
#     granted ONLY to the attestation-pinned image-digest window, so unsealing
#     requires a fresh Confidential Space attestation of a measured lineage
#     image -- the Confidential Space equivalent of vTPM/measured-boot sealing
#     (workloads have no direct vTPM access).
#
# Renewals rotate the live listener in place via setSecureContext; the old
# compute.instanceAdmin.v1 self-reset binding is gone (no VM reset anywhere
# in the TLS path).
# ============================================================================

resource "google_kms_key_ring" "acme_renewer" {
  name       = "auth-broker-acme-renewer"
  location   = var.region
  depends_on = [google_project_service.cloudkms]
}

resource "google_kms_crypto_key" "renewer_governance_signer" {
  name     = "renewer-governance-signer"
  key_ring = google_kms_key_ring.acme_renewer.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "renewer_signer" {
  crypto_key_id = google_kms_crypto_key.renewer_governance_signer.id
  role          = "roles/cloudkms.signerVerifier"
  member        = local.wif_principal
}

resource "google_kms_crypto_key_iam_member" "renewer_signer_viewer" {
  crypto_key_id = google_kms_crypto_key.renewer_governance_signer.id
  role          = "roles/cloudkms.viewer"
  member        = local.wif_principal
}

resource "google_kms_crypto_key_iam_member" "renewer_signer_candidates" {
  for_each      = toset(local.candidate_wif_principals)
  crypto_key_id = google_kms_crypto_key.renewer_governance_signer.id
  role          = "roles/cloudkms.signerVerifier"
  member        = each.value
}

resource "google_kms_crypto_key_iam_member" "renewer_signer_viewer_candidates" {
  for_each      = toset(local.candidate_wif_principals)
  crypto_key_id = google_kms_crypto_key.renewer_governance_signer.id
  role          = "roles/cloudkms.viewer"
  member        = each.value
}

# Persistent ACME account key. Generated on first run by the in-TEE renewer
# and sealed via addVersion. Compromise is bounded: the holder can ask LE for
# orders, but DNS-01 still requires the DNS-TEE quorum + scope predicate.
resource "google_secret_manager_secret" "acme_account_key" {
  secret_id = local.secret_ids.acme_account_key

  replication {
    auto {}
  }
}

# TLS-sealing key: wraps the 32-byte DEK of the sealed TLS capsule (and ONLY
# the DEK -- the TLS private key never reaches KMS). cryptoKeyEncrypterDecrypter
# is the gate that makes the capsule "sealed to the TEE": only a workload whose
# Confidential Space attestation carries an image digest in the current window
# can unwrap, so a lineage-continuity boot (roll candidate, successor
# activation, same-image restart) can carry the in-enclave cert forward while
# nothing outside the measured lineage can ever decrypt it.
resource "google_kms_crypto_key" "tls_sealing" {
  name     = "tls-sealing"
  key_ring = google_kms_key_ring.acme_renewer.id
  purpose  = "ENCRYPT_DECRYPT"

  # New primary every 90d; old versions stay decryptable so existing capsules
  # keep unsealing, and every renewal/re-seal re-wraps under the new primary.
  rotation_period = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "tls_sealing_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.tls_sealing.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = local.wif_principal
}

resource "google_kms_crypto_key_iam_member" "tls_sealing_encrypter_decrypter_candidates" {
  for_each      = toset(local.candidate_wif_principals)
  crypto_key_id = google_kms_crypto_key.tls_sealing.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = each.value
}

# Surface the renewer signer key version so authoritative-dns-tee operators
# can read the public key fingerprint to image-bake into EXTERNAL_TEE_RENEWERS.
output "renewer_governance_signer_key_version" {
  value = "${google_kms_crypto_key.renewer_governance_signer.id}/cryptoKeyVersions/1"
}

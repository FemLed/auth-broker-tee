# ============================================================================
# In-TEE ACME renewer (DNS-01 via authoritative-dns-tee). TLS is EPHEMERAL.
#
# This file provisions:
#   - ECDSA P-256 governance signer key in Cloud KMS, image-baked-fingerprinted
#     into authoritative-dns-tee's EXTERNAL_TEE_RENEWERS.
#   - `auth-broker-tee-acme-account-key` Secret Manager secret for the
#     persistent ACME account key.
#
# TLS private keys have NO at-rest form. The leaf key+cert are minted fresh in
# enclave memory on every cold boot (src/acme-renewal.js) and rotated in place
# via setSecureContext; nothing is sealed to KMS or written to GCS/Secret
# Manager. This deliberately removes the previous sealed-TLS capsule so that a
# GCP project/org IAM owner -- who can self-grant KMS decrypt -- has no
# ciphertext to unwrap. The trade-off is that each boot consumes a Let's
# Encrypt issuance (guarded by the non-secret mint ledger in src/tls-mint-log.js).
#
# The former `tls-sealing` ENCRYPT_DECRYPT key is RETIRED below (all IAM grants
# removed); see the note on that resource for the post-cutover destroy step.
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

# RETIRED: the `tls-sealing` ENCRYPT_DECRYPT key formerly wrapped the DEK of the
# sealed TLS capsule. TLS is now ephemeral (minted fresh in-enclave every boot,
# never persisted), so NO principal is granted encrypt/decrypt on this key -- a
# GCP project/org IAM owner therefore has nothing to unwrap. `prevent_destroy`
# is cleared so a follow-up apply can destroy the key entirely.
#
# CUTOVER (operator, after the ephemeral image is confirmed active): delete the
# stale `tls/oauth-tee.tls-capsule.v1.json` object from the capsule bucket, then
# remove this resource in a follow-up apply to destroy the key. Until then the
# key exists with no IAM bindings and no ciphertext referencing it.
resource "google_kms_crypto_key" "tls_sealing" {
  name     = "tls-sealing"
  key_ring = google_kms_key_ring.acme_renewer.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = false
  }
}

# Surface the renewer signer key version so authoritative-dns-tee operators
# can read the public key fingerprint to image-bake into EXTERNAL_TEE_RENEWERS.
output "renewer_governance_signer_key_version" {
  value = "${google_kms_crypto_key.renewer_governance_signer.id}/cryptoKeyVersions/1"
}

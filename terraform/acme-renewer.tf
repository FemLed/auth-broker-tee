# ============================================================================
# In-TEE ACME renewer (Path B + VM reset).
#
# The previous renewer talked to Cloudflare's DNS API directly via the
# `auth-broker-cloudflare-dns-token` Secret Manager secret. After the DNS
# authority cutover that token has no authority over `_acme-challenge.*`
# records on `femled.ai`, so the renewer is being ported onto
# authoritative-dns-tee's external-TEE-renewer trust path.
#
# This file provisions the new infrastructure:
#   - ECDSA P-256 governance signer key in Cloud KMS, image-baked-fingerprinted
#     into authoritative-dns-tee's EXTERNAL_TEE_RENEWERS.
#   - `auth-broker-tee-acme-account-key` Secret Manager secret for the
#     persistent ACME account key (replaces the per-renewal fresh keys the
#     old code generated).
#   - Single-instance-conditioned compute.instanceAdmin.v1 binding so the
#     renewer can reset its own VM at the end of a successful renewal.
#
# It also DELETES the legacy `auth-broker-cloudflare-dns-token` Secret
# Manager secret and its IAM binding -- the env var contract is no longer
# read at boot, so leaving the secret around would be operator footgun.
# Do this in a follow-up apply once dry-run has succeeded; until then keep
# the secret to support the bridge path.
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

# compute.instances.reset on this VM only. Scoped via IAM Conditions so the
# WIF principal cannot reset any other instance in the project.
resource "google_project_iam_member" "renewer_self_reset" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = local.wif_principal

  # Live VMs are now created by the build-and-attest workflow with names of
  # the form `auth-broker-tee-candidate-<digest12>`, not the historic fixed
  # name `auth-broker-tee`. Match by prefix so the renewer can reset its own
  # current candidate without widening the IAM grant beyond this VM family.
  condition {
    title       = "Reset only auth-broker-tee VM"
    description = "Renewer may reset its own VM after successful TLS renewal"
    expression  = "resource.type == \"compute.googleapis.com/Instance\" && resource.name.startsWith(\"projects/${var.project_id}/zones/${var.zone}/instances/auth-broker-tee\")"
  }
}

resource "google_project_iam_member" "renewer_self_reset_candidates" {
  for_each = toset(local.candidate_wif_principals)
  project  = var.project_id
  role     = "roles/compute.instanceAdmin.v1"
  member   = each.value

  condition {
    title       = "Reset only auth-broker-tee VM (candidate)"
    description = "Candidate renewer may reset its own VM after successful TLS renewal"
    expression  = "resource.type == \"compute.googleapis.com/Instance\" && resource.name.startsWith(\"projects/${var.project_id}/zones/${var.zone}/instances/auth-broker-tee\")"
  }
}

# Surface the renewer signer key version so authoritative-dns-tee operators
# can read the public key fingerprint to image-bake into EXTERNAL_TEE_RENEWERS.
output "renewer_governance_signer_key_version" {
  value = "${google_kms_crypto_key.renewer_governance_signer.id}/cryptoKeyVersions/1"
}

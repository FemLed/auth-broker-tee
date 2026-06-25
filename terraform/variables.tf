variable "project_id" {
  description = "GCP project ID for the auth broker"
  type        = string
  default     = "prod-femled-couple-router"
}

variable "project_number" {
  description = "GCP project number for the auth broker (used in WIF audience)"
  type        = string
  default     = "125139120897"
}

variable "region" {
  description = "GCP region for the Confidential VM"
  type        = string
  default     = "us-west1"
}

variable "zone" {
  description = "GCP zone for the Confidential VM"
  type        = string
  default     = "us-west1-b"
}

variable "machine_type" {
  # Vestigial: the auth-broker-tee VM is created by the build-and-attest /
  # operator-genesis workflows (Intel TDX, c3), not by Terraform. Kept only
  # for documentation; changing it here does not provision the VM.
  description = "Workflow-managed Confidential VM machine type (Intel TDX, c3-standard family)"
  type        = string
  default     = "c3-standard-4"
}

variable "container_image_digest" {
  description = "SHA-256 digest of the active container image (e.g. sha256:abc123...). Used in the WIF attestation condition to restrict secret access to this exact image. Reconciled from the live TEE governance manifest by scripts/reconcile-active-tee-iam.mjs into terraform/active-tee.reconciled.auto.tfvars.json."
  type        = string
}

variable "candidate_image_digests" {
  description = "Temporary successor candidate image digests allowed to read the broker's bootstrap secrets during predecessor-approved activation. Keep empty except during a handoff window."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for digest in var.candidate_image_digests : can(regex("^sha256:[a-f0-9]{64}$", digest))])
    error_message = "candidate_image_digests entries must be sha256 digests."
  }
}

# ---------------------------------------------------------------------------
# Supply-chain attestation pinning
#
# These variables encode WHICH GitHub Actions workflow is allowed to push
# images to Artifact Registry AND whose Sigstore-signed images the
# Confidential Space VM and WIF principal will accept. Changing any of
# these pins is a public, audit-logged Terraform diff -- which is exactly
# the property we want for "future-operator cannot quietly retarget the
# trust chain to a different repo/branch/workflow."
#
# Mirror of the GitHub OIDC `job_workflow_ref` claim:
#   <repo>/<workflow_path>@<branch>
# e.g. "FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master"
# ---------------------------------------------------------------------------
variable "gh_repo" {
  description = "GitHub repository (owner/name) whose Actions workflow signs auth-broker-tee builds"
  type        = string
  default     = "FemLed/auth-broker-tee"
}

variable "gh_branch_ref" {
  description = "Git ref the build workflow must run on for its Sigstore signatures to be honored"
  type        = string
  default     = "refs/heads/master"
}

variable "gh_workflow_path" {
  description = "Path of the workflow file within the repo (used to build the Fulcio cert SAN matcher)"
  type        = string
  default     = ".github/workflows/build-and-attest.yml"
}

variable "sigstore_oidc_issuer" {
  description = "OIDC issuer URL used by Sigstore Fulcio for the GitHub Actions identity"
  type        = string
  default     = "https://token.actions.githubusercontent.com"
}

variable "fulcio_root_url" {
  description = "Sigstore Fulcio root cert URL (cosign uses this to anchor signatures)"
  type        = string
  default     = "https://fulcio.sigstore.dev"
}

variable "rekor_url" {
  description = "Sigstore Rekor base URL"
  type        = string
  default     = "https://rekor.sigstore.dev"
}

# ---------------------------------------------------------------------------
# Confidential Space signed-image enforcement (KMS / Cosign)
#
# Confidential Space exposes verified image signatures via
# `assertion.submods.container.image_signatures`, but only when (a) the
# launcher is told where to look for the Cosign signatures via
# `tee-signed-image-repos`, and (b) those signatures were produced with
# one of the supported asymmetric key algorithms (ECDSA_P256_SHA256,
# RSASSA_PSS_SHA256, RSASSA_PKCS1V15_SHA256). Keyless Sigstore signatures
# are NOT honored by Confidential Space's signed-image flow today -- they
# remain useful for the public Rekor transparency story (verified by the
# external `verifier/` binary), but cannot gate launch or WIF.
#
# We therefore sign every image twice in build-and-attest.yml:
#   1. Keyless (Fulcio + Rekor) for the public chain.
#   2. With a Cloud KMS asymmetric key (this resource) for Confidential
#      Space's signed-image flow.
#
# The expected public-key fingerprint is hex-SHA256 of the DER-encoded
# public key:
#   openssl pkey -pubin -in pubkey.pem -outform DER | openssl sha256
# Terraform deliberately does not derive this from the KMS public-key PEM:
# the correct fingerprint hashes DER bytes, while Terraform's base64decode
# only returns UTF-8 strings. The build workflow prints the fingerprint
# using openssl; paste that value here.
# ---------------------------------------------------------------------------
variable "image_signature_repo" {
  description = "Artifact Registry image path where Cosign writes the KMS-signed signature artifact. Passed to the Confidential Space launcher via `tee-signed-image-repos`. For this image, Cosign stores signatures as tags like `auth-broker-tee:sha256-<digest>.sig`, so this must include the image name, not just the Artifact Registry repository."
  type        = string
  default     = "us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee"
}

variable "expected_image_signer_fingerprint" {
  description = "Hex SHA-256 fingerprint of the Cosign public key the WIF principal will trust. NO DEFAULT on purpose: compute it from the KMS public key with openssl or copy it from the build-and-attest workflow output. Rotating the KMS key requires updating this value (and going through the dual-fingerprint window in SUPPLY_CHAIN_BOOTSTRAP.md), so silent key swaps cannot happen."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.expected_image_signer_fingerprint))
    error_message = "expected_image_signer_fingerprint must be 64 hex characters (a sha256 of the DER-encoded public key)."
  }
}

variable "expected_image_signer_fingerprint_old" {
  description = "OPTIONAL hex SHA-256 fingerprint of the previous Cosign public key. When non-empty, the WIF condition accepts EITHER this fingerprint or `expected_image_signer_fingerprint`. Use only during a key rotation window: set this to the outgoing fingerprint, deploy a new image signed with the new key, then drop this variable back to empty once no live image relies on the old key. Documented in SUPPLY_CHAIN_BOOTSTRAP.md Step 9."
  type        = string
  default     = ""
  validation {
    condition     = var.expected_image_signer_fingerprint_old == "" || can(regex("^[0-9a-f]{64}$", var.expected_image_signer_fingerprint_old))
    error_message = "expected_image_signer_fingerprint_old must be empty or 64 hex characters."
  }
}

# ---------------------------------------------------------------------------
# External audit sink for KMS IAM mutations
#
# The KMS signing key is the load-bearing piece of the dual-signature
# trust model. Anyone who can grant themselves `cloudkms.signer` on
# this key can produce a Confidential Space-acceptable signature.
# Cloud Audit Logs in this project record every IAM mutation, but if
# the operator can also suppress logs in the same project, the audit
# trail is paper-thin. Set this to the resource name of an EXTERNAL
# log sink (storage bucket / pub/sub / BigQuery / org-level log
# router) -- ideally one whose IAM is owned by a different identity
# than this GCP project's owners. The Terraform resource
# `google_logging_project_sink.kms_audit_export` only ships when this
# variable is non-empty.
# ---------------------------------------------------------------------------
variable "kms_audit_log_sink_destination" {
  description = "Optional destination URI for streaming KMS Cloud Audit Logs to an external sink (e.g. `storage.googleapis.com/<bucket-in-different-org>` or `pubsub.googleapis.com/projects/<other-project>/topics/<topic>`). When empty, the sink is not provisioned -- but the audit_config below still records the events in this project's logs."
  type        = string
  default     = ""
}

variable "cosign_kms_key_algorithm" {
  description = "KMS asymmetric key algorithm Cosign uses to sign the image. Must match one of the values Confidential Space supports for image_signatures.signature_algorithm."
  type        = string
  default     = "EC_SIGN_P256_SHA256"
  validation {
    condition     = contains(["EC_SIGN_P256_SHA256", "RSA_SIGN_PSS_2048_SHA256", "RSA_SIGN_PKCS1_2048_SHA256"], var.cosign_kms_key_algorithm)
    error_message = "cosign_kms_key_algorithm must be a Confidential Space-supported algorithm."
  }
}

variable "cosign_kms_attestation_signature_algorithm" {
  description = "How the chosen KMS key surfaces in `image_signatures[].signature_algorithm`. Used in the WIF CEL condition. Must correspond to var.cosign_kms_key_algorithm."
  type        = string
  default     = "ECDSA_P256_SHA256"
  validation {
    condition     = contains(["ECDSA_P256_SHA256", "RSASSA_PSS_SHA256", "RSASSA_PKCS1V15_SHA256"], var.cosign_kms_attestation_signature_algorithm)
    error_message = "cosign_kms_attestation_signature_algorithm must be a Confidential Space-supported value."
  }
}

variable "cosign_kms_keyring_id" {
  description = "ID of the Cloud KMS keyring that holds the Cosign signing key for Confidential Space"
  type        = string
  default     = "auth-broker-cosign"
}

variable "cosign_kms_key_id" {
  description = "ID of the Cloud KMS asymmetric key used by Cosign to sign auth-broker-tee images"
  type        = string
  default     = "image-signer"
}

variable "route_firestore_collection" {
  description = "Firestore collection path in prod-femled-couple-router that transports TEE-admitted tenant route documents. Firestore is untrusted transport only; document signatures are load-bearing."
  type        = string
  default     = "auth_broker_route_documents"
}

# ---------------------------------------------------------------------------
# Enforcement toggles
#
# These exist so the bootstrap sequence in SUPPLY_CHAIN_BOOTSTRAP.md can
# land Terraform changes incrementally without bricking the running TEE.
#
#   enforce_signed_image_at_launch  -> Adds tee-signed-image-repos so
#                                      Confidential Space discovers
#                                      signatures and publishes verified
#                                      image_signatures claims.
#   enforce_signed_image_in_wif     -> WIF token mint requires the
#                                      attestation token to expose a
#                                      matching image signature claim.
#
# Both default to false so Terraform-apply during initial rollout is
# safe; flip to true only after a successfully-attested build is the
# running production image.
# ---------------------------------------------------------------------------
variable "enforce_signed_image_at_launch" {
  description = "If true, adds tee-signed-image-repos metadata so Confidential Space discovers Cosign signatures and exposes verified image_signatures claims. This does not by itself refuse VM launch; WIF enforcement is controlled by enforce_signed_image_in_wif."
  type        = bool
  default     = false
}

variable "enforce_signed_image_in_wif" {
  description = "If true, the WIF attribute_condition refuses to mint tokens for an image whose attestation token does not expose a matching KMS Cosign signature fingerprint."
  type        = bool
  default     = false
}

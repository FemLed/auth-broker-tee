variable "project_id" {
  description = "GCP project ID for the auth broker"
  type        = string
  default     = "prod-femled-couple-router"
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
  description = "Machine type for the Confidential VM (must be n2d for AMD SEV)"
  type        = string
  default     = "n2d-standard-2"
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token for DNS management"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for femled.ai"
  type        = string
  default     = "b9391961e5c7b2f5c1ab99cfc958f613"
}

# ---------------------------------------------------------------------------
# Secret values -- passed at apply time, never stored in state plaintext
# ---------------------------------------------------------------------------

variable "google_oauth_client_id" {
  description = "Google OAuth Client ID from the prod-femled-couple-router consent screen"
  type        = string
  sensitive   = true
}

variable "google_oauth_client_secret" {
  description = "Google OAuth Client Secret"
  type        = string
  sensitive   = true
}

variable "hmac_secret" {
  description = "HMAC secret for signing OAuth state parameters"
  type        = string
  sensitive   = true
}

variable "broker_api_key" {
  description = "API key shared between the broker and tenant backends"
  type        = string
  sensitive   = true
}

variable "gcp_sa_key_json" {
  description = "JSON key for the service account used to access Firestore (router-sa)"
  type        = string
  sensitive   = true
}

variable "tls_cert_pem" {
  description = "TLS certificate PEM for oauth-tee.femled.ai"
  type        = string
  sensitive   = true
}

variable "tls_key_pem" {
  description = "TLS private key PEM for oauth-tee.femled.ai"
  type        = string
  sensitive   = true
}

variable "container_image" {
  description = "Full Artifact Registry path to the auth-broker container image"
  type        = string
}

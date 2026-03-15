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
  description = "Machine type for the Confidential VM (must be n2d for AMD SEV)"
  type        = string
  default     = "n2d-standard-2"
}

variable "container_image" {
  description = "Full Artifact Registry path to the auth-broker container image"
  type        = string
}

variable "container_image_digest" {
  description = "SHA-256 digest of the container image (e.g. sha256:abc123...). Used in the WIF attestation condition to restrict secret access to this exact image."
  type        = string
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token for DNS management (Zone DNS Edit for femled.ai)"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for femled.ai"
  type        = string
  default     = "b9391961e5c7b2f5c1ab99cfc958f613"
}

# Auth Broker Attestation Verification Guide

This document explains how any FemLed couple or independent auditor can
cryptographically verify that the auth-broker running in the Confidential Space
TEE is the exact code published in this repository, with no modifications,
no logging, and no ability for FemLed operators to inspect traffic.

## What You Are Verifying

1. The container image running in the TEE was built from a specific git commit
   in this public repository.
2. The TEE is running the production Confidential Space image (not debug).
3. The `log_redirect` launch policy is active (operator cannot capture logs).
4. The `allow_cmd_override` launch policy is active (operator cannot change the
   container entrypoint).
5. TLS terminates inside the TEE — the load balancer sees only encrypted bytes.

---

## Option A: SLSA Provenance Verification (Recommended)

This verifies that Google Cloud Build produced the container image from a
specific git commit. You trust Google Cloud Build as an honest builder.

### Prerequisites

Install the SLSA verifier:

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

### Steps

```bash
# 1. Get the image reference (ask FemLed or read from Terraform output)
IMAGE="us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee:latest"

# 2. Verify SLSA provenance
slsa-verifier verify-image "$IMAGE" \
  --source-uri github.com/femled/auth-broker-tee \
  --source-tag v1.0.0

# 3. If verification passes, the image was built by Google Cloud Build
#    from the specified source repository and tag.
```

### What This Proves

- The image was built by Google Cloud Build (not on someone's laptop).
- The source came from the specified git repository and commit.
- The provenance is signed by Google's infrastructure, not by FemLed.

---

## Option B: Reproducible Build Verification (Zero Trust)

This verifies the image by rebuilding it yourself from source. You trust
nothing except your own machine and the TEE hardware.

### Prerequisites

- Docker with BuildKit support (Docker 23+)
- Git

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/femled/auth-broker-tee
cd auth-broker-tee

# 2. Check out the version you want to verify
git checkout v1.0.0

# 3. Build with deterministic settings
docker build --build-arg SOURCE_DATE_EPOCH=0 -t local-verify .

# 4. Get the local image digest
LOCAL_DIGEST=$(docker inspect --format='{{.Id}}' local-verify)
echo "Local digest: $LOCAL_DIGEST"

# 5. Compare with the digest from the TEE attestation token
#    (see "Attestation Token Verification" below)
echo "TEE digest:   $TEE_DIGEST"

# 6. If they match, the audited source code IS what's running.
```

---

## Attestation Token Verification

The Confidential Space TEE produces attestation tokens that cryptographically
prove what code is running. These tokens are signed by Google's attestation
service and contain the container image digest, debug status, and launch
policies.

### Requesting an Attestation Token

The auth-broker exposes an attestation endpoint that returns the current
TEE attestation token:

```bash
curl https://oauth-tee.femled.ai/attestation
```

### Verifying the Token

The attestation token is a JWT signed by Google. Verify it against Google's
OIDC public keys:

```bash
# 1. Fetch Google's Confidential Space JWKS
JWKS_URL="https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"

# 2. Decode the JWT and verify the signature using any JWT library

# 3. Check these claims in the verified token:
```

| Claim | Expected Value | What It Proves |
|---|---|---|
| `dbgstat` | `disabled-since-boot` | Production image, not debug. No SSH possible. |
| `swname` | `CONFIDENTIAL_SPACE` | Running on Confidential Space (AMD SEV TEE). |
| `submods.container.image_digest` | `sha256:...` | Exact container image running. Compare with your local build or SLSA provenance. |
| `submods.container.cmd_override` | `[]` or absent | Container CMD has not been overridden by the operator. |
| `submods.container.env_override` | (check for unexpected vars) | No unexpected environment variables injected. |

### Full Verification Checklist

- [ ] Attestation token signature is valid (signed by Google)
- [ ] `dbgstat` = `disabled-since-boot` (production image)
- [ ] `swname` = `CONFIDENTIAL_SPACE`
- [ ] `container.image_digest` matches your locally-built digest (Option B)
      OR matches the SLSA-verified image digest (Option A)
- [ ] `container.cmd_override` is empty (entrypoint not tampered with)
- [ ] Source code at the verified git commit contains no PII logging,
      no userinfo fetch, no data exfiltration
- [ ] The `log_redirect` launch policy label is present in the Dockerfile
- [ ] The `allow_cmd_override` launch policy label is present in the Dockerfile

---

## What the Source Code Guarantees

Review the source code at the verified git commit. Confirm:

1. **No userinfo fetch**: There is no call to
   `googleapis.com/oauth2/v2/userinfo`. The broker never requests the
   user's email from Google.

2. **No email in deposit payload**: The deposit payload sent to the tenant
   backend contains only `access_token`, `refresh_token`, `id_token`,
   `expiry_date`, `scope`, and `token_type`. No `userinfo` field.

3. **No PII in logs**: All `console.log` and `console.error` statements
   reference only tenant UUIDs and HTTP status codes. No email addresses,
   names, or user identifiers appear in any log statement.

4. **Launch policy blocks logging**: Even if the operator tries to enable
   Cloud Logging, the `tee.launch_policy.log_redirect=false` label in the
   Dockerfile prevents it.

5. **TLS terminates inside the TEE**: The server creates an HTTPS listener
   with cert/key loaded from Secret Manager into encrypted memory. The
   Network Load Balancer does TCP passthrough only.

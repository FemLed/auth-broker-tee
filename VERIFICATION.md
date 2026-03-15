# Verification Guide

This document explains how to cryptographically verify that the auth-broker
running in the Confidential Space TEE is the exact code published in this
repository, with no modifications, no logging, and no ability for FemLed
operators to inspect traffic.

If you are not technical, forward this document to your security team.

## What You Are Verifying

1. The source code in this repository does not log, store, or transmit
   any personally identifiable information.
2. The container image running in the TEE was built from this source code.
3. The TEE is running the production Confidential Space image (not debug).
4. The `log_redirect` launch policy is active (operator cannot capture logs).
5. The `allow_cmd_override` launch policy is active (operator cannot change
   the container entrypoint).
6. TLS terminates inside the TEE -- the load balancer sees only encrypted
   bytes.

---

## Step 1: Audit the Source Code

Review the source code at the commit you want to verify. Confirm:

- [ ] `src/routes.js` -- No call to `googleapis.com/oauth2/v2/userinfo`.
      The broker never requests the user's email from Google.
- [ ] `src/routes.js` -- The deposit payload contains only `access_token`,
      `refresh_token`, `id_token`, `expiry_date`, `scope`, `token_type`.
      There is no `userinfo` field.
- [ ] `src/routes.js` -- No `console.log` or `console.error` references
      email, name, or user profile data.
- [ ] `Dockerfile` -- `LABEL "tee.launch_policy.log_redirect"="never"`.
      This prevents the operator from enabling Cloud Logging.
- [ ] `Dockerfile` -- `LABEL "tee.launch_policy.allow_cmd_override"="false"`.
      This prevents the operator from changing the container entrypoint.
- [ ] `Dockerfile` -- Base image pinned by SHA-256 digest (not a mutable tag).
- [ ] `src/server.js` -- TLS server created with `https.createServer()`.
- [ ] `src/tls.js` -- TLS cert/key loaded from Secret Manager (gated by
      attestation), not from disk or environment variables.

---

## Step 2: Build the Image Yourself

Clone the repository and build the container image on your own machine.
This produces a cryptographic digest that you will compare against the
TEE attestation token in Step 3.

### Prerequisites

- Docker with BuildKit support (Docker 23+)
- Git

### Steps

```bash
git clone https://github.com/FemLed/auth-broker-tee
cd auth-broker-tee

# Check out the commit you audited in Step 1
git checkout <commit-or-tag>

# Build with deterministic settings
docker build --build-arg SOURCE_DATE_EPOCH=0 -t local-verify .

# Record the digest
LOCAL_DIGEST=$(docker inspect --format='{{.Id}}' local-verify)
echo "Your locally-built digest: $LOCAL_DIGEST"
```

Keep this digest. You will compare it in Step 3.

---

## Step 3: Verify the TEE Attestation Token

The Confidential Space TEE produces attestation tokens -- cryptographically
signed JWTs issued by Google's attestation service -- that prove the exact
container image running inside the sealed environment.

### Obtain the Attestation Token

```bash
curl -s https://oauth-tee.femled.ai/attestation
```

### Verify the Token Signature

The token is a JWT signed by Google. Verify it against Google's
Confidential Space OIDC public keys:

```
Discovery URL: https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
```

Use any standard JWT library to validate the signature.

### Check the Claims

After verifying the signature, inspect the following claims:

| Claim | What to check | What it proves |
|---|---|---|
| `submods.container.image_digest` | Matches `$LOCAL_DIGEST` from Step 2 | The audited source code is what's running |
| `dbgstat` | `disabled-since-boot` | Production image. No SSH access possible. |
| `swname` | `CONFIDENTIAL_SPACE` | Running on Confidential Space (AMD SEV TEE) |
| `submods.container.cmd_override` | Empty (`[]`) or absent | Entrypoint has not been tampered with |
| `submods.container.env_override` | No unexpected variables | No unexpected environment variables injected |

If `image_digest` matches your locally-built digest and all other claims
pass, the code you audited in Step 1 is provably what is running inside
the sealed environment.

---

## Alternative: SLSA Provenance Verification

If you prefer not to build the image yourself, you can verify that
Google Cloud Build produced the image from this repository using SLSA
(Supply-chain Levels for Software Artifacts) provenance.

This approach trusts Google Cloud Build as an honest builder rather than
rebuilding the image yourself.

### Prerequisites

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

### Steps

```bash
IMAGE="us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee:latest"

slsa-verifier verify-image "$IMAGE" \
  --source-uri github.com/FemLed/auth-broker-tee
```

If verification passes, the image was built by Google Cloud Build from
this repository. The provenance is signed by Google's infrastructure,
not by FemLed.

You can then compare the verified image digest against the TEE attestation
token's `submods.container.image_digest` claim.

---

## Complete Verification Checklist

- [ ] Source code audited (Step 1) -- no PII logging, no userinfo fetch
- [ ] Image built locally (Step 2) -- digest recorded
- [ ] Attestation token obtained (Step 3) -- signature valid (signed by Google)
- [ ] `dbgstat` = `disabled-since-boot` (production image)
- [ ] `swname` = `CONFIDENTIAL_SPACE`
- [ ] `container.image_digest` matches locally-built digest
- [ ] `container.cmd_override` is empty
- [ ] `log_redirect` launch policy label present in Dockerfile
- [ ] `allow_cmd_override` launch policy label present in Dockerfile

---

## Architecture

```
User Browser
    |
    | TLS (encrypted end-to-end)
    v
TCP Passthrough NLB (oauth-tee.femled.ai)
    |
    | Raw TCP (still encrypted)
    v
+-------------------------------------+
|  Confidential Space TEE (AMD SEV)   |
|                                     |
|  +-----------------------------+    |
|  |  TLS Termination            |    |
|  |  (cert + key in encrypted   |    |
|  |   memory from Secret Mgr)   |    |
|  +-------------+--------------+     |
|                v                    |
|  +-----------------------------+    |
|  |  Auth Broker (Node.js)      |    |
|  |  - Exchange OAuth code      |    |
|  |  - Deposit tokens to tenant |    |
|  |  - No userinfo fetch        |    |
|  |  - No PII logging           |    |
|  +-----------------------------+    |
|                                     |
|  No SSH | No logging | No memory   |
|  access | possible   | inspection  |
+-------------------------------------+
```

## Why the Image Digest Is Not in This File

Any change to a file in this repository changes the container image digest.
If the digest were listed here, it would be stale the moment it was
committed -- because committing it changes the file, which changes the
digest.

Instead, the live digest is obtained from the TEE attestation token
(Step 3) and compared against a local build (Step 2). This avoids the
self-referential problem entirely.

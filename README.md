# FemLed Auth Broker (Confidential Space TEE)

A zero-knowledge OAuth token broker that runs inside a Google Cloud
Confidential Space hardware Trusted Execution Environment (AMD SEV).

The broker exchanges Google OAuth authorization codes for tokens on behalf
of FemLed couples, without any ability for FemLed operators to inspect the
traffic or data flowing through it.

## Security Properties

- **TLS terminates inside the TEE** -- the Network Load Balancer does raw TCP
  passthrough; it never sees plaintext
- **No SSH access** -- the Confidential Space production image blocks SSH
- **No logging** -- the `log_redirect` launch policy prevents the operator from
  capturing stdout/stderr
- **No userinfo fetch** -- the broker never requests the user's email from Google
- **Encrypted memory** -- AMD SEV encrypts the VM's memory at the hardware level;
  even the hypervisor cannot read it
- **Attestable** -- external parties can cryptographically verify the exact code
  running in the TEE

## Current Deployment

| Property | Value |
|---|---|
| **Endpoint** | `https://oauth-tee.femled.ai` |
| **GCP Project** | `prod-femled-couple-router` |
| **Region** | `us-west1` |
| **Machine Type** | `n2d-standard-2` (AMD SEV) |
| **Confidential Space Image** | `confidential-space-260200` |

## Attestation Values

These values can be used to verify that the TEE is running the expected code.
They are updated with each release.

| Claim | Expected Value |
|---|---|
| **Container Image Digest** | `sha256:afaec62e9f59c5ebf8aa9787c8f2f30fe313d7679052b94d90116d1a55c62584` |
| **Artifact Registry** | `us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee` |
| **`swname`** | `CONFIDENTIAL_SPACE` |
| **`dbgstat`** | `disabled-since-boot` |
| **Launch Policy: `log_redirect`** | `false` |
| **Launch Policy: `allow_cmd_override`** | `false` |

## Verifying the TEE

Full verification instructions are in [VERIFICATION.md](VERIFICATION.md).

### Quick Check (SLSA Provenance)

```bash
slsa-verifier verify-image \
  us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee:latest \
  --source-uri github.com/FemLed/auth-broker-tee
```

### Reproducible Build

```bash
git clone https://github.com/FemLed/auth-broker-tee
cd auth-broker-tee
docker build --build-arg SOURCE_DATE_EPOCH=0 -t local-verify .
docker inspect --format='{{.Id}}' local-verify
# Compare with the Container Image Digest above
```

### Attestation Token

Request an attestation token from the TEE and verify:

1. `container.image_digest` matches the digest in the table above
2. `dbgstat` = `disabled-since-boot` (production image, no SSH)
3. `swname` = `CONFIDENTIAL_SPACE`
4. Launch policies confirm logging and CMD override are blocked

## Source Code Audit Checklist

When reviewing the source code at a given commit, confirm:

- [ ] `src/routes.js` -- No call to `googleapis.com/oauth2/v2/userinfo`
- [ ] `src/routes.js` -- Deposit payload contains only `access_token`,
      `refresh_token`, `id_token`, `expiry_date`, `scope`, `token_type`
      (no `userinfo` field)
- [ ] `src/routes.js` -- No `console.log` or `console.error` references email,
      name, or user profile data
- [ ] `Dockerfile` -- `LABEL "tee.launch_policy.log_redirect"="false"`
- [ ] `Dockerfile` -- `LABEL "tee.launch_policy.allow_cmd_override"="false"`
- [ ] `Dockerfile` -- Base image pinned by SHA-256 digest
- [ ] `src/server.js` -- TLS server created with `https.createServer()`
- [ ] `src/tls.js` -- TLS cert/key loaded from Secret Manager (gated by
      attestation), not from disk or environment variables

## Architecture

```
User Browser
    │
    │ TLS (encrypted end-to-end)
    ▼
TCP Passthrough NLB (oauth-tee.femled.ai)
    │
    │ Raw TCP (still encrypted)
    ▼
┌─────────────────────────────────────┐
│  Confidential Space TEE (AMD SEV)   │
│                                     │
│  ┌─────────────────────────────┐    │
│  │  TLS Termination            │    │
│  │  (cert + key in encrypted   │    │
│  │   memory from Secret Mgr)   │    │
│  └──────────┬──────────────────┘    │
│             ▼                       │
│  ┌─────────────────────────────┐    │
│  │  Auth Broker (Node.js)      │    │
│  │  - Exchange OAuth code      │    │
│  │  - Deposit tokens to tenant │    │
│  │  - No userinfo fetch        │    │
│  │  - No PII logging           │    │
│  └─────────────────────────────┘    │
│                                     │
│  No SSH │ No logging │ No memory    │
│  access │ possible   │ inspection   │
└─────────────────────────────────────┘
```

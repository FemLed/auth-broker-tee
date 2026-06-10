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
7. **The image was built by the canonical GitHub Actions workflow on
   `master`, signed by Sigstore (keyless, public Rekor entry), AND
   signed by a GCP KMS key whose `cloudkms.signer` IAM is granted only
   to that workflow's service account.** Both signatures are produced
   in the same workflow run on the same digest. The keyless signature
   is the public-transparency layer the standalone verifier checks
   (Step 4). The KMS signature is what Confidential Space's launcher
   and WIF attribute-condition mechanically check (Step 5).
   Confidential Space launch enforcement and WIF token-mint
   enforcement are gated by the
   `enforce_signed_image_at_launch` and `enforce_signed_image_in_wif`
   variables in `terraform.tfvars`; those toggles are `true` in the
   live deployment described here. Verify by reading the production
   `terraform.tfvars`.
8. **The image can only be approved and signed after TEE-owned FemLed
   First Principles adjudication.** The live broker exposes
   `POST /first-principles/adjudicate`, calls Vertex AI Gemini through
   `@google/genai` from inside the TEE, and returns a canonical verdict
   bound to a Google Confidential Space attestation token whose `eat_nonce`
   is the verdict payload digest. The GitHub workflow verifies that
   attestation-bound verdict before PR auto-approval or push-side image
   signing. GitHub-orchestrated governance POST endpoints require a GitHub
   Actions OIDC token for audience `https://oauth-tee.femled.ai/governance`
   from the canonical `build-and-attest.yml` workflow on `master`; public
   verification manifests remain readable without caller auth. Tenant admission
   is separate: it requires a tenant-signed registration envelope proving
   control of the submitted route key. For TEE successor activation
   specifically, the early `/governance/preapprove` verdict is bound to a
   short-lived `/governance/challenge` for the exact preapproval request digest,
   GitHub workflow run, and GitHub SHA but is not final authority: the active TEE performs a second
   activation-time Gemini arbitration over a canonical successor decision packet
   after it has verified the inactive candidate's attestation nonce, image
   digest, governance key, activation key, hard-check evidence, and predecessor
   lineage context.
9. **The running TEE publishes self-governance lineage.** The broker exposes
   `GET /.well-known/femled-tee-governance.json`, whose payload is bound to
   a Confidential Space attestation nonce. The governance lineage is a chain
   of Ed25519-signed genesis/successor certificates. A successor should be
   treated as active only when it is in this predecessor-signed lineage and
   the manifest reports `status: active`. There is intentionally no admin
   recovery key: if the active TEE dies before successor handoff, governance
   bricks instead of falling back to a GitHub or GCP owner.
10. **Self-healing is advisory until successor activation.** The governance
   manifest may include health telemetry, model-policy digest, and signed
   self-healing proposal digests. These help repair workers build candidate
   artifacts, but they are not activation authority. GitHub PRs, green CI,
   Cloud Build success, Artifact Registry images, callback updates, and
   admin approval UI do not make a successor active. Only the full
   predecessor-signed activation protocol can mutate TEE identity, route
   privileges, model policy, governance state, or TEE-owned state:
   activation-time Gemini APPROVE over the canonical decision packet, candidate
   application of the encrypted transfer bundle, candidate-signed activation
   proof, and predecessor finalization/retirement.
11. **Tenant pin refresh is tenant-polled post-activation maintenance.**
   Tenant servers intentionally hard-pin the accepted broker trust state. After
   a predecessor-signed successor becomes active, each tenant polls the live
   attested governance and policy manifests, verifies lineage continuity from
   its own previously accepted state, and updates only its own local Secret
   Manager trust state. This keeps tenants strict without giving tenants,
   operators, or the broker repository authority over TEE activation.
12. **Closed-loop repair may automate candidate production, not authority.**
   The active TEE may turn unresolved health degradation into a signed repair
   proposal and launch a constrained mini-swe-agent repair worker. That worker
   may produce source bundles, build/test summaries, and candidate image
   digests. It may not receive GitHub write tokens, governance keys,
   activation keys, KMS signer rights, WIF policy rights, route mutation
   rights, or permission to
   mark a TEE active. Investigation-agent artifacts are also evidence only.
   An inactive candidate deployment is only a process that can present
   attestation and receive an activation bundle; it becomes active only after
   predecessor-signed preapproval, activation-time Gemini successor acceptance,
   successor certificate issuance, encrypted state transfer, activation apply,
   and predecessor finalization after candidate proof.

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
- [ ] `src/server.js` -- TLS server created with `https.createServer()` from
      in-memory material only.
- [ ] `src/tls-capsule.js` + `src/acme-renewal.js` -- the TLS private key is
      minted in-enclave via ACME at genesis and carried across
      lineage-continuity boots through the KMS-sealed, attestation-gated GCS
      capsule. It is never read from or written to Secret Manager, disk, or
      environment variables; renewals rotate in place via
      `server.setSecureContext()`.
- [ ] `src/first-principles-adjudication.js` -- The adjudication endpoint
      verifies GitHub Actions OIDC, binds the signed verdict to the exact
      repo/head SHA/diff digest/compliance digest/workflow run/nonce, and
      signs with the TEE-held key.
- [ ] `src/vertex-gemini.js` -- Gemini requests use `@google/genai` with
      Vertex AI and attestation-bound GCP credentials, never a static API key.
- [ ] `src/first-principles-review.js` -- The policy preserves FemLed's
      mission, consent, transparency, behavioral accountability, tenant
      trust pinning, and failure-closed review requirements.
- [ ] `src/route-registry.js` -- Tenant route records loaded from Firestore
      or another mutable transport are accepted only after verifying a
      TEE-signed tenant admission certificate and a tenant-key-signed route
      envelope. Legacy mutable `couples` fields such as `api_url` are not
      route authority.
- [ ] `src/governance-state.js` and `src/governance-crypto.js` -- Governance
      private keys are in-memory only, privileged routes require active
      governance, and successor activation requires predecessor-signed
      lineage plus nonce-bound candidate attestation.
- [ ] `src/governance-routes.js` -- GitHub-orchestrated governance POST
      endpoints require canonical GitHub Actions OIDC, apply local rate limits
      before expensive work, and require `/governance/preapprove` to consume a
      one-time challenge bound to the canonical preapproval request digest,
      workflow run, and SHA. `/governance/tenant-admission` requires a
      tenant-signed registration envelope rather than GitHub identity.
- [ ] `src/governance-monitor.js` and `src/governance-repair-contract.js` --
      Self-healing telemetry is sanitized and in-memory, repair-worker output
      is treated as untrusted evidence, and model upgrades remain image-baked
      successor changes rather than runtime pointers.
- [ ] `src/governance-self-improvement.js`, `src/governance-repair-jobs.js`,
      and `src/governance-repair-launcher.js` -- Closed-loop repair launches
      only constrained candidate-builder jobs. Job status, callbacks, PRs, and
      candidate submissions are evidence, not approval or activation.

---

## Step 2: Build the Image Yourself

Clone the repository and build the container image on your own machine.
This produces a cryptographic digest that you will compare against the
TEE attestation token in Step 3.

### Prerequisites

- Docker with BuildKit support (Docker 23+). Docker Desktop 4.34+ is
  recommended (containerd image store enabled by default).
- Git

### Steps

```bash
git clone https://github.com/FemLed/auth-broker-tee
cd auth-broker-tee

# Check out the commit you audited in Step 1
git checkout <commit-or-tag>

# Create a docker-container builder (matches Cloud Build's environment)
docker buildx create --name repro --driver docker-container --use

# Reproducible build
docker buildx build \
  --builder repro \
  --platform linux/amd64 \
  --provenance=false \
  --sbom=false \
  --no-cache \
  --build-arg SOURCE_DATE_EPOCH=0 \
  --output type=docker,rewrite-timestamp=true,unpack=false,oci-mediatypes=false \
  -t local-verify .

# Record the digest
LOCAL_DIGEST=$(docker inspect --format='{{.Id}}' local-verify)
echo "Your locally-built digest: $LOCAL_DIGEST"
```

**What the flags do:**

| Flag | Purpose |
|---|---|
| `--platform linux/amd64` | Matches the Cloud Build target architecture |
| `--provenance=false` | Prevents BuildKit from wrapping the image in a manifest list with attestation manifests (which changes the digest) |
| `--sbom=false` | Same -- prevents SBOM attestation manifest |
| `--no-cache` | Forces a clean build with no stale layers |
| `--build-arg SOURCE_DATE_EPOCH=0` | Sets the reference timestamp for `rewrite-timestamp` |
| `--builder repro` | Uses the `docker-container` builder, which runs the same BuildKit version as Cloud Build (`moby/buildkit:buildx-stable-1`) |
| `--output type=docker,rewrite-timestamp=true,unpack=false` | Rewrites all file timestamps in every layer to the `SOURCE_DATE_EPOCH` value, eliminating non-determinism from `npm ci` and other build steps |

Keep this digest. You will compare it in Step 3.

### Troubleshooting

If the digest does not match the TEE attestation token:

- Confirm you checked out the exact commit that was deployed, not a later
  commit. The commit hash is visible in the Artifact Registry image tag.
- Confirm `--provenance=false` and `--sbom=false` are present. Without
  them, Docker Desktop wraps the image in a manifest list with extra
  attestation manifests, producing a different top-level digest.
- Confirm `rewrite-timestamp=true` is in the `--output` flag. Without it,
  file timestamps from `npm ci` vary between runs.
- Confirm `--platform linux/amd64` is present. Building for a different
  architecture (e.g. `arm64` on Apple Silicon) produces a different image.
- Confirm you created and used a `docker-container` builder with
  `docker buildx create`. The default Docker Desktop builder uses a
  different BuildKit version, producing different layer digests.

---

## Step 3: Verify the TEE Attestation Token

The Confidential Space TEE produces attestation tokens -- cryptographically
signed JWTs issued by Google's attestation service -- that prove the exact
container image running inside the sealed environment.

### Obtain the Attestation Token

Generate a random nonce (8-88 bytes) and request a fresh attestation token:

```bash
NONCE=$(openssl rand -hex 16)
curl -s "https://oauth-tee.femled.ai/attestation?nonce=${NONCE}" > attestation.jwt
echo "Nonce: $NONCE"
```

The response is a JWT signed by Google's attestation service with a custom
audience (`https://oauth-tee.femled.ai`). This token cannot be used for
STS exchange -- it is safe to inspect and share with your security team.

### Verify the Token Signature

Verify the JWT against Google's Confidential Space OIDC public keys:

```
Discovery: https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
```

Use any standard JWT library to validate the signature. Confirm that:
- The `aud` claim is `https://oauth-tee.femled.ai`
- The `eat_nonce` claim contains the nonce you provided

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

### Verify the Broker Policy Manifest

Fetch the signed policy manifest:

```bash
curl -s "https://oauth-tee.femled.ai/.well-known/femled-tee-policy.json" > femled-tee-policy.json
```

Verify:

- `payload.schema` is `femled.tee.policy.v1`.
- `payload.imageDigest` matches `submods.container.image_digest` from the
  attestation JWT.
- `payload.genaiSdkRequired` is `true`.
- `payload.firstPrinciplesPromptDigest` matches the prompt digest pinned by
  the tenant.
- `payload.githubWorkflowIdentity` is
  `FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master`.
- `payloadDigest` equals the SHA-256 digest of the canonical JSON payload.
- `attestationToken` is signed by Google's Confidential Space issuer, has
  `dbgstat=disabled-since-boot`, `swname=CONFIDENTIAL_SPACE`, the expected
  image digest, and an `eat_nonce` containing `payloadDigest`.

This manifest is the tenant-facing commitment that a GCP owner can stop the
TEE, but cannot replace it with a less FemLed-committed broker that tenants
continue to trust.

---

## Step 4: Verify the Supply-Chain Attestation Chain

Steps 1-3 prove that *some* code with a given digest is running. Step 4
proves that the digest corresponds to source code which (a) was committed
to this exact GitHub repository, (b) was built by the exact CI workflow
in [.github/workflows/build-and-attest.yml](.github/workflows/build-and-attest.yml),
and (c) passed every check in [.compliance/](.compliance/) at build
time. The end-to-end verification is automated by the standalone Go
binary at [verifier/](verifier/).

### Build the verifier

```bash
cd verifier
go build -o verifier .
```

You also need `cosign` on PATH; the verifier shells out to it for the
Sigstore signature + Fulcio cert + Rekor lookup. See
[verifier/README.md](verifier/README.md) for details.

### Run the verifier

```bash
./verifier
```

This:

1. Generates a random nonce and asks the live TEE for a fresh attestation
   token.
2. Verifies the JWT signature against Google's Confidential Space JWKS.
3. Asserts `swname=CONFIDENTIAL_SPACE`, `dbgstat=disabled-since-boot`,
   `submods.gce.project_id` matches expected, and the nonce echoes back.
4. Extracts the running image digest.
5. Runs `cosign verify` against that digest, requiring the Fulcio cert
   SAN to match `https://github.com/FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master`
   and the OIDC issuer to be `https://token.actions.githubusercontent.com`.
6. Runs `cosign verify-attestation` to fetch the in-toto compliance
   predicate, confirms `overall_status: passed`, and prints the rules
   digest.
7. Confirms the build workflow required a signed TEE First Principles
   adjudication before signing the image.
8. Optionally asserts the rules digest equals a value you pinned with
   `--pinned-rules-digest`.

Exit 0 means the entire chain validated. Exit 1 means something in the
chain failed; the JSON output names the failing step. Exit 2 means a
configuration / installation problem.

### Pin the rules digest

The first time you verify, capture the current rules digest:

```bash
# Capture stderr to a file rather than discarding it -- a `cosign not on
# PATH` error would otherwise be silently swallowed.
RULES_DIGEST=$(./verifier 2> verifier.err | jq -r '.compliance_rules_digest')
echo "$RULES_DIGEST"
```

Then on every subsequent run (and especially in any cron / monitoring
script you set up), pass `--pinned-rules-digest "$RULES_DIGEST"` so any
weakening of the compliance rules is caught immediately.

### Run from cron on a non-FemLed-controlled machine

This is the load-bearing assumption. If you run the verifier only on
FemLed-owned infrastructure, FemLed could subvert the verifier itself.
Run it from your own laptop, your own VPS, your own SOC -- somewhere
FemLed cannot edit the cron entry. Hook the failure path into whatever
paging system you use.

```cron
*/15 * * * * /usr/local/bin/verifier --pinned-rules-digest sha256:... --fail-on-skip || curl -X POST $WEBHOOK
```

### Look up the Sigstore entry by hand

If you prefer to inspect Rekor directly:

```bash
DIGEST=$(curl -s https://oauth-tee.femled.ai/attestation \
  | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq -r '.submods.container.image_digest')
rekor-cli search --sha "${DIGEST#sha256:}"
```

The `subject` of every Rekor entry will encode the GitHub workflow
identity. If the subject does not match the canonical workflow on
`main`, the image is not honest -- regardless of what FemLed claims.

---

## Step 5: What the Confidential Space Launch Policy and WIF Condition Enforce

Steps 1-4 are *external* verification that anyone can perform. Step 5
documents the *internal* enforcement: when the toggles below are set
to `true` in production `terraform.tfvars`, the system itself refuses
to operate on a non-signed image. Read the production `terraform.tfvars`
to confirm the toggles are on; they are NOT enforced by default in the
file as committed (the bootstrap runbook flips them only after a
freshly attested image is the running production image).

There are two enforcement points, each gated by an independent
Terraform variable so the bootstrap sequence can land them
incrementally (see [SUPPLY_CHAIN_BOOTSTRAP.md](SUPPLY_CHAIN_BOOTSTRAP.md)):

### `enforce_signed_image_at_launch`

When `true` in `terraform.tfvars`, the Confidential VM metadata sets:

- `tee-signed-image-repos = <var.image_signature_repo>`

The Confidential Space launcher (which runs *outside* the workload's
TEE memory) then discovers Cosign signatures attached to the running
image in that repo, verifies them against the supported asymmetric
algorithms, and surfaces every verified signature as an entry in the
`assertion.submods.container.image_signatures` claim of the
attestation token.

**Important honest caveat.** This metadata key by itself does NOT
make the VM refuse to launch unsigned images. It only enables
signature *discovery* and adds verified entries to the attestation
token. The actual enforcement -- "no Secret Manager access for an
image whose signatures don't match our key" -- happens in the WIF
clause below. An unsigned image will boot, attempt to fetch its
secrets via WIF, fail because the CEL condition rejects the token,
and crash on startup; it does not run with stale or missing secrets.

### `enforce_signed_image_in_wif`

When `true`, the WIF `attribute_condition` on
`google_iam_workload_identity_pool_provider.attestation_verifier`
(in [terraform/main.tf](terraform/main.tf)) gains an additional clause
that pins to the exact KMS-key fingerprint:

```cel
['ECDSA_P256_SHA256:<expected_image_signer_fingerprint>'].exists(
  fingerprint,
  fingerprint in assertion.submods.container.image_signatures
    .map(sig, sig.signature_algorithm + ':' + sig.key_id)
)
```

This means the federated STS exchange (which mints the access tokens
the workload uses to read Secret Manager) refuses to issue any token
unless the attestation token exposes a signature whose
`signature_algorithm:key_id` matches the fingerprint pinned in
`terraform.tfvars` as `expected_image_signer_fingerprint`.

### Honest assurance summary

The two enforcement points together mean a future-FemLed-operator
cannot quietly substitute a malicious image without a Cloud Audit
Logs / Terraform-diff trail visible to anyone with read access to
the GCP project AND the Terraform state. They do NOT, on their own,
prove the image came from `master` of this repo -- that link comes
from the keyless Sigstore signature verified by the standalone
[`verifier/`](verifier/) binary against Rekor (Step 4).

The mechanical gate is the KMS key + IAM grant. The public
transparency layer is keyless Sigstore + Rekor. Both are produced
by the same workflow on the same image digest.

### What to verify (Terraform)

- [ ] Production `terraform.tfvars` -- both
      `enforce_signed_image_at_launch` and
      `enforce_signed_image_in_wif` are set to `true`.
      `expected_image_signer_fingerprint` is set to the value printed
      by the build-and-attest workflow as `Cosign KMS key fingerprint`
      or computed from the KMS public key with openssl.
- [ ] [terraform/main.tf](terraform/main.tf) -- the
      `google_compute_instance.auth_broker.metadata` block injects
      `tee-signed-image-repos` when the launch toggle is on, and the
      `google_iam_workload_identity_pool_provider.attestation_verifier`
      `attribute_condition` interpolates
      `var.expected_image_signer_fingerprint` (NOT a live data-source
      lookup, so rotation requires a deliberate Terraform diff).
- [ ] [terraform/kms.tf](terraform/kms.tf) -- the KMS keyring + key
      exist, `prevent_destroy = true`, and the only IAM member on the
      key is the `gh_actions_publisher` SA with role
      `roles/cloudkms.signerVerifier`. No human members, no
      project-level binding.
- [ ] [terraform/supply-chain.tf](terraform/supply-chain.tf) -- the
      `gh_actions` WIF pool is the *only* identity allowed to push to
      the `auth-broker` Artifact Registry repo, and its
      `attribute_condition` pins
      `assertion.job_workflow_ref == 'FemLed/auth-broker-tee/.github/workflows/build-and-attest.yml@refs/heads/master'`
      and `assertion.event_name == 'push'`. No other workflow, no PR,
      no fork can mint a publisher token.

---

## How Secrets Are Accessed (Workload Identity Federation)

The broker uses
[Workload Identity Federation](https://docs.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources)
(WIF) to authenticate with Google Cloud using the Confidential Space
attestation token.

The flow:

1. The Confidential Space launcher writes a signed attestation token to
   `/run/container_launcher/attestation_verifier_claims_token`.
2. At startup, the broker reads this token and exchanges it with Google's
   Security Token Service (STS) for a federated access token.
3. The federated access token is used to fetch secrets from Secret Manager.

The WIF provider's attestation policy restricts access to workloads that:
- Run on `CONFIDENTIAL_SPACE` with a `STABLE` image
- Have a container image digest matching the expected value

Each Secret Manager secret has an IAM binding that grants
`secretAccessor` only to the federated identity matching the expected
image digest. The operator cannot grant access to a different image.

Successor handoff has one extra operational step: after the predecessor-signed
successor is active and production traffic serves its governance manifest, run
`scripts/reconcile-active-tee-iam.mjs` from outside the TEE. The reconciler
verifies the attested manifest with the existing verifier, checks the expected
image digest and predecessor lineage pin, and emits Terraform JSON variables
that promote the active digest to `container_image_digest` while removing it
from `candidate_image_digests`. The TEE never receives Terraform, IAM admin,
or policy mutation authority; it only publishes the signed evidence Terraform
operators must verify before applying digest-scoped bindings.

The secret names are **hardcoded in `src/server.js`** (auditable). The operator cannot influence which
secrets the workload reads.

### What to verify

- [ ] `src/server.js` -- The `SECRETS` object lists only the expected
      secret names. No unexpected secrets are accessed.
- [ ] `src/gcp-auth.js` -- Authentication uses the attestation token at
      `/run/container_launcher/attestation_verifier_claims_token`, not
      the metadata server (except for Firestore access which uses the
      VM service account).
- [ ] `Dockerfile` -- `allow_env_override` lists only non-sensitive
      config vars (`GCP_PROJECT_ID`, `GCP_PROJECT_NUMBER`,
      `REDIRECT_URI`, `GOOGLE_SCOPES`,
      `AUTH_BROKER_ROUTE_FIRESTORE_COLLECTION`). No secret names are listed.
- [ ] The WIF provider's attestation condition in Terraform matches the
      expected image digest and requires `CONFIDENTIAL_SPACE` + `STABLE`.

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
- [ ] `allow_env_override` lists only non-sensitive config vars
- [ ] Secrets accessed via WIF (not env vars or metadata)
- [ ] WIF attestation condition requires correct image digest + STABLE
- [ ] Verifier exits 0 against the live TEE (Step 4)
- [ ] For post-bootstrap monitoring, verifier pins the accepted
      governance lineage digest with `--pinned-governance-lineage-digest`
- [ ] For replacement verification, verifier rejects fresh parallel
      genesis with `--require-successor-lineage` and pins the predecessor
      lineage with `--pinned-predecessor-lineage-digest`
- [ ] After accepted successor activation, `scripts/reconcile-active-tee-iam.mjs`
      verifies the live successor manifest and emits Terraform variables that
      promote the successor digest to `container_image_digest` without granting
      the TEE IAM mutation authority.
- [ ] After accepted successor activation, tenant servers poll the live
      governance and policy manifests, verify predecessor-signed lineage
      continuity from their own accepted state, and update only tenant-local
      broker trust-state secrets.
- [ ] Tenant route private keys are tenant-held and non-exportable where
      possible. The central broker project, TEE VM service account, central
      repair workers, and central operators have no KMS signer/admin or
      service-account impersonation path for tenant route keys.
- [ ] `compliance_rules_digest` from the predicate matches the digest
      computed locally over `.compliance/`
- [ ] `enforce_signed_image_at_launch = true` in production
      `terraform.tfvars` (Step 5)
- [ ] `enforce_signed_image_in_wif = true` in production
      `terraform.tfvars` (Step 5)
- [ ] `expected_image_signer_fingerprint` in production
      `terraform.tfvars` equals the `key_id` value shown in the live
      `image_signatures` attestation claim AND
      `auth-broker-tee/terraform/kms.tf` IAM grants `cloudkms.signerVerifier`
      only to the GHA publisher SA (Step 5).
- [ ] Sigstore Rekor entry for the image's digest names the canonical
      GHA workflow on `master` as the signing identity
- [ ] Any successor certificate includes activation-time Gemini arbitration
      digests: `successorDecisionPacketDigest`,
      `successorArbitrationDigest`, and `arbitrationPhase:
      successor_acceptance`
- [ ] Privileged governance POSTs are not public resource triggers:
      `/governance/challenge` and `/governance/preapprove` require the
      governance-audience GitHub Actions OIDC token, preapproval certificates
      include the consumed challenge/request/auth binding digests, and public
      read-only manifests remain unauthenticated for independent verification.
- [ ] Tenant admission is rooted in tenant-held key control: admission
      requests include a tenant registration envelope signed by one of the
      submitted tenant route keys, and route registry refresh happens inside
      the TEE process rather than through a public refresh endpoint.

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
(Step 3), compared against a local build (Step 2), and cross-checked
against the Sigstore Rekor entry produced by the GitHub Actions workflow
(Step 4). The chain of cryptographic statements is:

```
git commit (signed)  ->  GHA workflow (OIDC-bound)  ->  Sigstore Rekor entry  ->  image digest
                                                                                       ^
                                                                                       |
                                                                       Confidential Space attestation token
                                                                                       |
                                                                                       v
                                                                                  WIF token mint
                                                                                       |
                                                                                       v
                                                                              Secret Manager access
```

Every arrow in that chain is publicly verifiable from outside FemLed
infrastructure. There is no point in the chain where the operator can
silently substitute a different image, because every substitution
requires a new public Rekor entry whose absence the verifier (and
launch policy, and WIF condition) will detect.
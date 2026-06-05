# Supply-Chain Attestation Bootstrap Runbook

This runbook walks you through landing the supply-chain attestation
pipeline (everything in `.github/workflows/`, `.compliance/`, `verifier/`,
and the new Terraform resources) without taking the running TEE
offline.

The order is load-bearing: tightening WIF or launch policy before the
running image carries a Sigstore signature will brick the broker
because the existing TEE will fail to mint Secret Manager tokens or
fail to launch on next restart.

If anything fails mid-sequence, every step has an explicit rollback.

---

## Prerequisites

Before starting:

- [ ] You have GCP project owner on `prod-femled-couple-router`.
- [ ] You have admin on the `FemLed/auth-broker-tee` GitHub repo.
- [ ] You have `terraform`, `gcloud`, `cosign`, `go`, `jq` installed
      locally.
- [ ] The repo's `master` branch already has all the file changes from
      this PR (compliance/, verifier/, .github/, Dockerfile, terraform/,
      etc.) merged but `enforce_signed_image_at_launch` and
      `enforce_signed_image_in_wif` are still `false` in
      `terraform.tfvars`.
- [ ] No deploy is in flight.

### Branch protection model

Master branch protection is status-check based. It requires:

- `compliance gate`
- `tee-first-principles-review`

There is intentionally no machine-user reviewer shim. GitHub PR reviews are
not the trust root for this repository; the signed, attested TEE First
Principles decision is the review gate. `FemLed-CI` may create branches,
open PRs, and merge only after the required status checks pass, but no
secondary reviewer token is needed to convert TEE approval into a fake
human-style PR approval.

---

## Step 1: Land the GHA WIF push-side Terraform

```bash
cd terraform
terraform plan -out plan.bin
# Review: should add google_iam_workload_identity_pool.gh_actions,
# google_iam_workload_identity_pool_provider.github_oidc,
# google_service_account.gh_actions_publisher,
# google_artifact_registry_repository_iam_member.gh_actions_writer,
# google_service_account_iam_member.gh_actions_wif_user.
# Should NOT modify the existing attestation_verifier provider OR the
# Confidential VM metadata.
terraform apply plan.bin
```

Capture the WIF provider path that `terraform output` prints; it should
match the value already hard-coded in
`.github/workflows/build-and-attest.yml`. If it doesn't, edit the
workflow file and push to a branch that does NOT trigger the workflow,
then merge.

**Rollback if anything goes wrong:** `terraform destroy -target=...`
on each new resource. The running TEE is untouched at this point.

---

## Step 1.5: Provision the KMS image-signing key and capture its fingerprint

The Cosign signature that Confidential Space mechanically validates
comes from a Google Cloud KMS asymmetric key. Provision it before the
first attested build (otherwise the `cosign sign --key gcpkms://...`
step in the workflow has nothing to call).

```bash
cd terraform
terraform plan \
  -target=google_project_service.cloudkms \
  -target=google_kms_key_ring.image_signing \
  -target=google_kms_crypto_key.image_signer \
  -target=google_kms_crypto_key_iam_member.gha_signer \
  -out plan.bin
# Review: should add the KMS API enablement, keyring, key, and a
# single IAM grant of roles/cloudkms.signerVerifier to the
# gh_actions_publisher SA. Nothing else.
terraform apply plan.bin
```

Capture the KMS key URI:

```bash
URI=$(terraform output -raw image_signer_kms_key_uri)
echo "kms_uri=${URI}"
```

Paste the URI into the
`COSIGN_KMS_KEY_URI` env block at the top of
`.github/workflows/build-and-attest.yml` if it differs from the
default (it normally won't). The first successful build-and-attest run
prints `Cosign KMS key fingerprint: ...`; paste that value into
`terraform.tfvars` as `expected_image_signer_fingerprint = "..."`.

**Rollback:** `terraform destroy -target=google_kms_crypto_key.image_signer`
fails because of `prevent_destroy`. Remove that lifecycle block in a
deliberate Terraform change if you really need to delete the key (you
almost never do; rotate the key version instead -- see Step 9).

### Wire up the external KMS audit-log sink (strongly recommended)

The KMS key is the load-bearing piece of the dual-signature trust
model. Cloud Audit Logs in `prod-femled-couple-router` already
record every IAM mutation and signing operation against this key,
but if a future-operator can also edit Cloud Logging in the same
project they can suppress that trail. Mitigate by exporting those
events to a sink in a different trust domain.

Create the destination bucket / pubsub topic / BigQuery dataset in
a project NOT owned by FemLed's GCP-admin identities (a personal GCP
project, a customer SOC, an OSSF-managed bucket -- anything off the
critical path). Then:

1. Set `kms_audit_log_sink_destination` in `terraform.tfvars` to the
   destination URI (see the example file for shapes).

2. `terraform apply`. Capture the writer identity:

   ```bash
   WRITER=$(terraform output -raw kms_audit_sink_writer_identity)
   echo "$WRITER"
   ```

3. Grant that writer identity write access on the destination. For a
   GCS bucket:

   ```bash
   gcloud storage buckets add-iam-policy-binding gs://<bucket> \
     --member="${WRITER}" \
     --role=roles/storage.objectCreator
   ```

   (For pub/sub: `roles/pubsub.publisher`. For BigQuery:
   `roles/bigquery.dataEditor`.)

4. Trigger a benign event (e.g. `gcloud kms keys versions list ...`)
   and confirm it shows up in the destination within a few minutes.

If you can't set this up immediately, the audit_config still records
events in this project's logs -- just be aware the trust trade-off
documented in README.md weakens from "Terraform diff in audit log
the operator can't suppress" to "Terraform diff in audit log the
operator could suppress."

---

## Step 2: Trigger the first attested build

Push any trivial change to `master` (a comment-only commit is fine), or
re-run the workflow on the latest commit via GHA "Re-run all jobs."
Watch:

```bash
gh run watch --repo FemLed/auth-broker-tee
```

Confirm:

- [ ] `compliance` job passes (every check status `passed`).
- [ ] `build-and-sign` job passes.
- [ ] The "Reproducible build PASSED" message appears with two
      identical digests.
- [ ] The job summary at the bottom of the run page shows the new
      image digest, the rules digest, and a sample verifier
      invocation.

If the compliance job fails, fix the violation locally
(`bash .compliance/run.sh`), push, and re-run. Do NOT proceed until
the workflow is green.

---

## Step 3: Manually verify the new image with the standalone verifier

Build the verifier:

```bash
cd verifier
go build -o verifier .
```

Verify the brand-new image (it is in Artifact Registry but not yet
deployed to the VM):

```bash
IMAGE_DIGEST=<from GHA job summary>
RULES_DIGEST=<from GHA job summary>

cosign verify \
  --certificate-identity-regexp "^https://github\\.com/FemLed/auth-broker-tee/\\.github/workflows/build-and-attest\\.yml@refs/heads/master$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee@${IMAGE_DIGEST}

cosign verify-attestation \
  --certificate-identity-regexp "^https://github\\.com/FemLed/auth-broker-tee/\\.github/workflows/build-and-attest\\.yml@refs/heads/master$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type "https://femled.ai/attestations/auth-broker-compliance/v1" \
  us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee@${IMAGE_DIGEST} \
  | jq '.payload | @base64d | fromjson | .predicate'
```

Both must succeed and the predicate JSON must show
`overall_status: "passed"` and the matching `compliance_rules_digest`.

---

## Step 4: Sample a live attestation token to confirm CEL schema

Before flipping `enforce_signed_image_in_wif`, we must confirm the
exact path Confidential Space exposes for `image_signatures` in the
attestation token.

The current production TEE is still running an unsigned image, so the
token will *not* yet have the `image_signatures` field populated. Do
this step *after* Step 5 (deploy the signed image) but *before*
Step 7 (flip the WIF toggle).

For now, just record what fields are present:

```bash
NONCE=$(openssl rand -hex 16)
TOKEN=$(curl -s "https://oauth-tee.femled.ai/attestation?nonce=${NONCE}")
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.submods.container'
```

Note the keys present. We expect to see `image_digest`,
`image_reference`, possibly `cmd_override`, `env_override`. The
`image_signatures` field will appear AFTER Step 5 deploys a signed
image. Document the exact key name and shape in your local notes.

---

## Step 5: Deploy the freshly-attested image to the running TEE

Update `terraform.tfvars` with the new image:

```hcl
container_image        = "us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee:<short-sha>"
container_image_digest = "sha256:<digest>"
```

Apply and recreate the VM so it pulls the new image:

```bash
terraform apply
terraform taint google_compute_instance.auth_broker
terraform apply
```

Wait ~3 minutes for the VM to come back up, then sanity-check:

```bash
curl -sSf https://oauth-tee.femled.ai/health
```

Should return `{"status":"ok"}`.

**If the new image fails to start**, the VM will retry per
`tee-restart-policy = Always`. Roll back by reverting `container_image`
and `container_image_digest` in `terraform.tfvars` and re-applying.

---

## Step 6: Confirm the running TEE's attestation token now exposes the signature claim

Re-run the token-sample command from Step 4:

```bash
NONCE=$(openssl rand -hex 16)
TOKEN=$(curl -s "https://oauth-tee.femled.ai/attestation?nonce=${NONCE}")
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.submods.container'
```

You should now see an `image_signatures` array with at least one
entry; each entry has `signature_algorithm` (e.g.
`ECDSA_P256_SHA256`) and `key_id` (hex SHA-256 of the public key).
Confirm:

- `signature_algorithm == ECDSA_P256_SHA256` (or whatever you set
  `cosign_kms_attestation_signature_algorithm` to).
- `key_id` matches the value in `terraform.tfvars` as
  `expected_image_signer_fingerprint`.

If either differs, the WIF CEL clause that pins
`<algorithm>:<fingerprint>` will reject every token; STOP and fix the
mismatch before Step 7. Common causes: the workflow signed with a
different KMS key version than expected (rotate via Step 9), or the
`signature_algorithm` enum string differs from the docs (sample the
live token to learn the correct one).

Run the standalone verifier end-to-end against the live TEE:

```bash
./verifier --pinned-rules-digest "${RULES_DIGEST}"
```

Must exit 0.

---

## Step 7: Tighten the WIF condition

In `terraform.tfvars`:

```hcl
enforce_signed_image_in_wif = true
```

Apply:

```bash
terraform plan -out plan.bin
# Review: ONLY changes
# google_iam_workload_identity_pool_provider.attestation_verifier
# attribute_condition (adds the
# `[ECDSA_P256_SHA256:<fingerprint>].exists(...)` clause that pins
# the WIF identity to the exact KMS public-key fingerprint).
terraform apply plan.bin
```

The next time the running TEE refreshes its WIF token (within ~30
minutes given the cache TTL in `gcp-auth.js`), the new condition
applies. Watch:

```bash
# Wait for the in-process token cache to expire (max 1h), then trigger a
# fresh secret read by hitting an endpoint that uses one. /push/send-silent
# requires the broker API key, which is loaded at startup, so this is
# more about confirming nothing crashes.
curl -sSf https://oauth-tee.femled.ai/health
```

If the VM logs show STS exchange failures with a CEL evaluation error,
the schema in Step 6 was wrong. Roll back by setting
`enforce_signed_image_in_wif = false` and re-applying. Then fix the
CEL expression to match the actual attestation token shape, push to
main (regenerating signed image), redeploy, and try again.

---

## Step 8: Enable signature discovery at launch

This adds `tee-signed-image-repos` to the VM metadata so the
Confidential Space launcher discovers Cosign signatures and surfaces
them in the attestation token. It does NOT by itself refuse to start
unsigned images -- the actual "won't run a malicious image" property
is the WIF CEL clause already enforced in Step 7. After this step,
unsigned images will still boot but will fail at `loadSecrets()`
because the WIF token mint rejects them.

In `terraform.tfvars`:

```hcl
enforce_signed_image_at_launch = true
```

Apply:

```bash
terraform plan -out plan.bin
# Review: ONLY changes
# google_compute_instance.auth_broker.metadata
# (adds the supported `tee-signed-image-repos = <signature repo>`
# metadata key so the launcher discovers and verifies our Cosign
# signatures and surfaces them in `submods.container.image_signatures`).
terraform apply plan.bin
```

Then taint the VM and re-apply so the new launch policy takes effect
on the next boot:

```bash
terraform taint google_compute_instance.auth_broker
terraform apply
```

If the launcher rejects the image (you'll see this in serial console
output), most likely either (a) the launcher cannot find the Cosign
signature in the configured `tee-signed-image-repos` repo, or (b)
the Confidential Space metadata key name has changed in a recent CS
release. Confirm against
https://cloud.google.com/confidential-computing/confidential-space/docs/reference/metadata-variables
and adjust `terraform/main.tf` accordingly.

---

## Step 9: KMS key rotation procedure (dual-fingerprint window)

The mechanical enforcement gate trusts a single KMS key fingerprint.
Rotating the key naively would brick the running broker the moment
the new fingerprint is pinned but no image has been signed with the
new key. Use this dual-window pattern instead:

1. **Create a new key version** (does NOT touch the live one):

   ```bash
   gcloud kms keys versions create \
     --location=us-west1 \
     --keyring=auth-broker-cosign \
     --key=image-signer
   ```

2. **Capture the new fingerprint** after promoting/signing with the new
   key version by either copying `Cosign KMS key fingerprint: ...` from
   the build-and-attest workflow log, or computing it locally:

   ```bash
   cosign public-key --key gcpkms://projects/prod-femled-couple-router/locations/us-west1/keyRings/auth-broker-cosign/cryptoKeys/image-signer > cosign-kms.pub
   openssl pkey -pubin -in cosign-kms.pub -outform DER | openssl dgst -sha256
   ```

3. **Open the dual-fingerprint window** by setting BOTH fingerprints
   in `terraform.tfvars`:

   ```hcl
   expected_image_signer_fingerprint     = "<NEW fingerprint from step 2>"
   expected_image_signer_fingerprint_old = "<CURRENT live fingerprint>"
   ```

   The WIF CEL condition uses
   `local.accepted_image_signer_celset` (in
   [terraform/kms.tf](terraform/kms.tf))
   which automatically expands to a two-element CEL list when the
   `_old` variable is non-empty, so no `main.tf` edit is needed.
   Apply:

   ```bash
   terraform apply
   ```

4. **Promote the new key version** so future signing uses it:

   ```bash
   gcloud kms keys versions update \
     --location=us-west1 \
     --keyring=auth-broker-cosign \
     --key=image-signer \
     --version=<new-version> \
     --primary
   ```

   Trigger a fresh build-and-attest run (Step 2). The new build is
   signed with the new key version; its `image_signatures.key_id`
   matches the NEW fingerprint.

5. **Deploy the new image** (Step 5). The dual-fingerprint CEL
   accepts it. Confirm via `/attestation` that `image_signatures[].key_id`
   is the new fingerprint.

6. **Close the dual-fingerprint window** once the new image is live
   and the old image is no longer reachable (delete its tags, wait
   for any cached WIF tokens to expire). Set
   `expected_image_signer_fingerprint_old = ""` in `terraform.tfvars`
   and `terraform apply`. The CEL list collapses back to a single
   accepted fingerprint.

7. **Disable the old key version** (does not delete; KMS retains it
   for audit history):

   ```bash
   gcloud kms keys versions disable \
     --location=us-west1 \
     --keyring=auth-broker-cosign \
     --key=image-signer \
     --version=<old-version>
   ```

8. **Communicate the new fingerprint** in release notes so external
   verifiers can update their `--pinned-rules-digest` (the rules
   digest also changes if `.compliance/` was touched).

If you need to roll back at any point during the window, both
fingerprints are accepted, so reverting to the old image and old
`terraform.tfvars` value is a single `terraform apply`.

---

## Step 10: Final verification

From a non-FemLed machine (your laptop, a personal VPS, anywhere not
under FemLed control), run:

```bash
./verifier --pinned-rules-digest "${RULES_DIGEST}" --pinned-image-digest "${IMAGE_DIGEST}"
```

After the trusted genesis or accepted successor is live, record the governance
lineage digest:

```bash
LINEAGE_DIGEST=$(./verifier 2>/dev/null | jq -r '.governance.lineageDigest')
```

Steady-state monitors should pin it:

```bash
./verifier \
  --pinned-rules-digest "${RULES_DIGEST}" \
  --pinned-governance-lineage-digest "${LINEAGE_DIGEST}"
```

Replacement verification must reject fresh parallel genesis and require the
candidate to extend the accepted predecessor lineage:

```bash
./verifier \
  --pinned-rules-digest "${RULES_DIGEST}" \
  --pinned-predecessor-lineage-digest "${LINEAGE_DIGEST}" \
  --require-successor-lineage \
  --min-governance-epoch 2
```

During a successor handoff, open a temporary candidate WIF window in
`terraform.tfvars` before launching the inactive candidate:

```hcl
candidate_image_digests = ["${CANDIDATE_IMAGE_DIGEST}"]
```

Apply that change so the inactive candidate can fetch the same bootstrap
secrets as the active TEE. Remove the candidate digest after the handoff
finalizes and the new image becomes the primary `container_image_digest`.

Use the strict activation orchestrator to perform the predecessor-approved
handoff:

```bash
node scripts/activate-successor.mjs \
  --candidate-ip "${CANDIDATE_IP}" \
  --image-digest "${CANDIDATE_IMAGE_DIGEST}" \
  --workflow-run-id "${WORKFLOW_RUN_ID}"
```

Run the script from the canonical GitHub Actions workflow with `id-token:
write`, or pass a governance-audience token explicitly with
`--governance-oidc-token` / `AUTH_BROKER_GOVERNANCE_OIDC_TOKEN`. Privileged
governance POSTs accept only GitHub Actions OIDC tokens whose audience is
`https://oauth-tee.femled.ai/governance` and whose workflow identity is the
canonical `build-and-attest.yml` workflow on `master`.

The script includes the GitHub workflow run ID and head SHA in the source
bundle, then asks `/governance/challenge` for a short-lived, one-time challenge
bound to the canonical `/governance/preapprove` request digest. The active TEE
rejects preapproval unless those source-bundle fields match the GitHub OIDC
`run_id` and `sha`. It then performs preapproval, activation offer,
nonce-bound candidate attestation, activation-time Gemini arbitration,
candidate bundle application, and predecessor finalization in order. If any
step fails, the predecessor must remain non-retired.

After production traffic points at the active successor, reconcile the
digest-scoped WIF/IAM bindings from outside the TEE. Use the reconciliation
command printed by `activate-successor.mjs`, or run the equivalent explicitly:

```bash
node scripts/reconcile-active-tee-iam.mjs \
  --expected-image-digest "${CANDIDATE_IMAGE_DIGEST}" \
  --pinned-predecessor-lineage-digest "${LINEAGE_DIGEST}" \
  --min-governance-epoch 2 \
  --candidate-image-digest "${CANDIDATE_IMAGE_DIGEST}" \
  --write-default-tfvars-json
```

Review `terraform/active-tee.reconciled.auto.tfvars.json`, then run
`terraform plan` and `terraform apply` from `terraform/`. This promotes the
attested active successor digest to `container_image_digest` and removes it
from the temporary candidate window. Do not give the TEE runtime Terraform,
IAM admin, or policy mutation permissions; the TEE supplies signed lineage
evidence, while Terraform remains the audited infrastructure mutation path.

After a successor is active and verified, tenants poll the live, attested
governance and policy manifests from their own projects. Each tenant verifies
that the published lineage extends its previously accepted broker state, then
updates its own local trust-state Secret Manager value and runtime pin cache.
The broker repository must not contain tenant GCP project IDs, tenant Secret
Manager targets, or tenant rollout commands. Tenant polling is trust-pin
maintenance only; it does not approve, activate, or replace a TEE.

(Strict mode is the default as of 2026-05; `--fail-on-skip` was
removed -- skipped checks now fail the verifier unless you pass the
deprecated `--lax`.)

Exit 0 means the entire chain is intact and enforced. Set up a cron
that runs this every 15 minutes and pages on non-zero exit.

Update the public release notes (or homepage) with:

- The pinned image digest
- The pinned rules digest
- The pinned governance lineage digest
- The Sigstore Rekor entry URL
- The verifier binary's checksum (so customers can audit it themselves)

---

## What to do when you intentionally rotate

When you legitimately update the broker (bug fix, feature add):

1. Open a PR. The `compliance` job runs and posts the new rules digest
   if `.compliance/` changed.
2. Land the PR. The `build-and-sign` job produces a new attested
   image. The new image's digest and the new rules digest appear in
   the job summary.
3. If the rules digest changed, communicate the new digest in the
   release notes. External verifiers that pinned the old digest will
   start alerting; they need to update their pin.
4. Update `container_image_digest` in `terraform.tfvars` and apply.
   Taint the VM. The signed-image launch policy auto-validates the
   new digest's Sigstore signature.

There is no "skip CI for this hotfix" lever. If you want one, you'd
have to add it to the workflow, which is itself a PR -- that's the
property.
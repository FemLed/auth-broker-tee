# auth-broker-tee verifier

A small Go binary that asks a running auth-broker TEE for a fresh
attestation token and confirms the entire supply-chain chain end-to-end:
the JWT is signed by Google's Confidential Space attestation service, the
running image is signed in Sigstore by the expected GitHub Actions
workflow on the expected repo + branch, and the signed in-toto compliance
predicate shows every check passed. It also verifies the live
`/.well-known/femled-tee-governance.json` manifest: the manifest payload
must be nonce-bound to Confidential Space attestation, report active
governance, match the attested image digest, and contain a valid
Ed25519-signed governance lineage from genesis to the current TEE.
The governance report also surfaces health status, model-policy digest, and
self-healing proposal digests when present. Successor certificates include
digests for the canonical successor decision packet and the activation-time
Gemini arbitration that authorized that successor. Those digests are the audit
handles for the active TEE's mission judgment; repair-worker artifacts, GitHub
PRs, CI results, and Cloud Build outputs remain evidence only and are not
accepted as activation authority.
Open self-healing proposal envelopes are verified against the current
governance key when present, so a verifier can distinguish TEE-signed repair
requests from untrusted repair-worker output. Repair job digests and statuses
are reporting fields; a failed or pending job is not by itself a verifier
failure.

If you are a customer, security auditor, or "future-you who wants to
catch present-you cheating," **run this binary from a machine that is
*not* under FemLed control, on a cron, and alert on any non-zero exit.**
That is the load-bearing assumption for the trust property described in
the project root README and VERIFICATION.md.

## Build

```bash
cd auth-broker-tee/verifier
go build -o verifier .
```

The resulting binary is statically-linkable and ~15 MB. You can
`go install ./...` instead if you prefer it on PATH.

## Runtime requirement: cosign on PATH

The verifier shells out to [`cosign`](https://docs.sigstore.dev/cosign/installation/)
for the actual Sigstore signature + Fulcio cert + Rekor lookup. This is a
deliberate design decision -- cosign is the official, audited Sigstore
CLI and reusing it keeps this verifier's bug surface small.

Install cosign once on your watcher machine:

```bash
# Example on Linux/amd64; see Sigstore docs for other platforms
curl -sSL -o /usr/local/bin/cosign \
  https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x /usr/local/bin/cosign
```

If `cosign` is not on PATH, the verifier exits 2 with a clear error.

## Usage

The minimal invocation accepts every default and verifies the production
deployment:

```bash
./verifier
```

The defaults are deliberately public values that match what the
`auth-broker-tee` repo publishes; you do not need a secret to run this.

The recommended invocation pins the rules digest the first time you
verify, so any later weakening of `.compliance/` is caught:

```bash
# First run: capture the current rules digest
RULES_DIGEST=$(./verifier 2>/dev/null | jq -r '.compliance_rules_digest')

# Subsequent runs: pin it
./verifier --pinned-rules-digest "$RULES_DIGEST"
```

If you also want to detect any image rotation (e.g., FemLed pushes a new
build whose contents you have not yet reviewed), pin the image digest
too:

```bash
./verifier --pinned-rules-digest sha256:... --pinned-image-digest sha256:...
```

After trusted genesis, also pin governance continuity. The image, GitHub
workflow, KMS signature, and Rekor entry are artifact evidence; the active TEE
identity is the predecessor-signed governance lineage. Capture the current
`lineageDigest` from a trusted verification run and use it for steady-state
monitoring:

```bash
LINEAGE_DIGEST=$(./verifier 2>/dev/null | jq -r '.governance.lineageDigest')
./verifier --pinned-rules-digest sha256:... --pinned-governance-lineage-digest "$LINEAGE_DIGEST"
```

When verifying a replacement, require that the candidate extends the currently
accepted lineage instead of presenting a fresh parallel genesis:

```bash
./verifier \
  --pinned-rules-digest sha256:... \
  --pinned-predecessor-lineage-digest "$LINEAGE_DIGEST" \
  --require-successor-lineage \
  --min-governance-epoch 2
```

**Strict by default.** As of 2026-05, the verifier requires every
expected compliance check to be present in the predicate AND have
status `passed`. Missing checks, `skipped`, empty, or unrecognized
statuses all fail the verifier. This is what you want when watching a
production TEE.

The verifier also rejects a TEE whose governance manifest is missing,
retired/inactive, not nonce-bound to attestation, or whose lineage does
not cryptographically lead to the attested image digest. This is separate
from GitHub/GCP provenance: a GCP owner may deploy a candidate image, but
without predecessor-signed governance lineage it is not treated as the
active FemLed TEE.

If you're temporarily verifying a predicate that legitimately has
skipped or missing checks (for example a local-dev predicate where
`syft` was unavailable), you can pass `--lax` as a bridge:

```bash
./verifier --pinned-rules-digest sha256:... --lax
```

`--lax` is **deprecated** and will be removed on 2026-11-01; do not
build production runbooks around it.

## Flags

| Flag                       | Default                                                                              | Purpose                                                                       |
|----------------------------|--------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `--tee-url`                | `https://oauth-tee.femled.ai`                                                        | Base URL of the TEE to verify (must expose `/attestation`).                   |
| `--expected-repo`          | `FemLed/auth-broker-tee`                                                             | GitHub repository the build workflow runs in.                                 |
| `--expected-workflow`      | `.github/workflows/build-and-attest.yml`                                             | Workflow file path within the repo.                                           |
| `--expected-branch`        | `refs/heads/master`                                                                  | Git ref the workflow must have run on.                                        |
| `--expected-project-id`    | `prod-femled-couple-router`                                                          | GCP project the TEE must be deployed in (per attestation `submods.gce`).      |
| `--pinned-rules-digest`    | (none)                                                                               | If set, predicate's `compliance_rules_digest` MUST equal this value.          |
| `--pinned-image-digest`    | (none)                                                                               | If set, the running image digest MUST equal this value.                       |
| `--pinned-governance-lineage-digest` | (none)                                                                      | If set, governance manifest lineageDigest MUST equal this value.              |
| `--pinned-predecessor-lineage-digest` | (none)                                                                    | If set, running lineage must extend this predecessor lineage by one successor. |
| `--require-successor-lineage` | `false`                                                                            | Reject fresh length-1 genesis lineage during replacement verification.        |
| `--min-governance-epoch`   | `0`                                                                                  | If greater than zero, governance epoch must be at least this value.            |
| `--expected-broker-sa`     | `auth-broker-tee@prod-femled-couple-router.iam.gserviceaccount.com`                  | SA that MUST appear in the attestation `google_service_accounts` claim.       |
| `--expected-image-repo-regexp` | `^us-west1-docker\.pkg\.dev/prod-femled-couple-router/auth-broker/auth-broker-tee(:|@)` | Regex the running `image_reference` MUST match.                          |
| `--allowed-env-override-keys` | `GCP_PROJECT_ID,GCP_PROJECT_NUMBER,REDIRECT_URI,GOOGLE_SCOPES,AUTH_BROKER_ROUTE_FIRESTORE_COLLECTION` | Keys allowed in `submods.container.env_override`. Mirrors Dockerfile.         |
| `--lax`                    | `false`                                                                              | DEPRECATED. Tolerates missing checks and `skipped` status. Removed 2026-11-01.|
| `--oidc-issuer`            | `https://token.actions.githubusercontent.com`                                        | Sigstore OIDC issuer (Fulcio cert iss).                                       |
| `--rekor-url`              | `https://rekor.sigstore.dev`                                                         | Rekor base URL (cosign uses this).                                            |
| `--cosign`                 | `cosign`                                                                             | Path to the cosign binary.                                                    |
| `--timeout`                | `90s`                                                                                | Overall verification timeout.                                                 |
| `--verbose`                | `false`                                                                              | Include the full predicate body in stdout (useful for first-pin runs).        |
| `--skip-attestation`       | `false`                                                                              | Skip predicate verification (signature-only mode).                            |
| `--jwks-discovery-url`     | `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration`      | OIDC discovery doc for the Confidential Space attestation issuer.             |

## Exit codes

| Code | Meaning                                                                              |
|-----:|--------------------------------------------------------------------------------------|
|    0 | Verified. Stdout is a JSON report with the image digest and check statuses.          |
|    1 | Verification failed. Stdout JSON contains `error` describing which step failed.      |
|    2 | Usage / configuration error (cosign not installed, bad flag, etc.).                  |

## Output shape

On success (`exit 0`):

```json
{
  "status": "passed",
  "nonce": "f1...32",
  "image_reference": "us-west1-docker.pkg.dev/.../auth-broker-tee:abc123",
  "image_digest": "sha256:fa1afe1...",
  "signature_verified": true,
  "compliance_rules_digest": "sha256:3650fc5b...",
  "compliance_check_statuses": [
    {"name": "semgrep",            "status": "passed"},
    {"name": "check_routes",       "status": "passed"},
    {"name": "check_secrets",      "status": "passed"},
    {"name": "check_imports",      "status": "passed"},
    {"name": "branch_protection",  "status": "passed"},
    {"name": "sbom",               "status": "passed"},
    {"name": "vuln_scan",          "status": "passed"}
  ],
  "attestation_claims": { ... }
}
```

On failure (`exit 1`):

```json
{
  "status": "",
  "error": "rules digest mismatch: predicate has sha256:abcd... but pinned sha256:1234...",
  "nonce": "f1...32",
  "image_digest": "sha256:fa1afe1...",
  "signature_verified": true
}
```

## Recommended cron pattern

On a non-FemLed-controlled host (your laptop, a personal VPS, a customer's
SOC, anywhere you trust more than FemLed's GCP):

```cron
*/15 * * * * /usr/local/bin/verifier \
  --pinned-rules-digest sha256:3650fc5b... \
  > /var/log/femled-attest/$(date -u +\%FT\%T).json 2>/var/log/femled-attest/$(date -u +\%FT\%T).err \
  || curl -sX POST "$WEBHOOK_URL" \
       -d "{\"text\": \"FemLed TEE attestation FAILED at $(date -u +\%FT\%T)\"}"
```

(Send stderr to its own file rather than discarding with `2>/dev/null`
so genuine errors -- e.g. cosign missing on PATH -- are not silently
swallowed.)

Hook the failure branch into whatever paging system you use; the failure
mode you care about is "auth-broker switched to an image that is not
signed by main" and you want to know within minutes.

## What you are NOT verifying

This tool verifies the supply chain of the running image. It does *not*
verify:

- The contents of FemLed's Cloud Audit Logs, Cloudflare DNS, or
  Secret Manager state. Those are out of scope.
- Per-couple coach workloads. Each couple's coach TEE has its own
  attestation chain in a different repo.
- Whether the image source code does what its README claims. That is
  what `VERIFICATION.md` Step 1 (manual code audit) is for; this tool
  proves only that *the audited code is what is running*.

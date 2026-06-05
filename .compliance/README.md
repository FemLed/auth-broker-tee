# auth-broker-tee Compliance Suite

This directory holds the rules and checkers that gate every build of the
auth-broker TEE image. Their results are signed into an in-toto attestation
predicate alongside the image's Sigstore signature, so any verifier can
prove that a given image digest was built from source that passed every
check listed here.

If you are reviewing this repository for the first time and asking "how do
I know FemLed cannot bypass this?" -- the answer is that the *rule set
itself* is part of the attestation. The sha256 of every file in this
directory (excluding `*.md`) is computed at build time, embedded in the
predicate as `compliance_rules_digest`, and visible to any verifier. If
FemLed weakens a rule, the next build's `compliance_rules_digest` will
differ, and verifiers that pinned the prior digest will refuse to consider
the new image attested.

## What runs

The orchestrator is [`run.sh`](run.sh). It executes the following checks
in order; any failure short-circuits the workflow.

| Check                    | Tool                       | Defends against                                                                                                  |
|--------------------------|----------------------------|------------------------------------------------------------------------------------------------------------------|
| `semgrep`                | Semgrep with `semgrep.yml` | Logging tokens/secrets to stdout; fs writes outside `tls.js`; forbidden module imports; unaudited HTTP servers; `eval`/`Function` |
| `check-routes`           | `acorn` AST walk           | Adding HTTP routes without updating `route-allowlist.json`                                                       |
| `check-secrets`          | `acorn` AST walk           | Adding Secret Manager secret reads without updating `secrets-allowlist.json` (and by extension Terraform IAM)    |
| `check-imports`          | `acorn` AST walk           | Pulling in any new module not on the explicit allowlist; dynamic `import(...)` with non-literal specifiers       |
| `check-route-integrity`  | custom source scan         | Regressing tenant routing to mutable Firestore fields instead of TEE-admitted, tenant-signed route documents     |
| `branch-protection`      | GitHub REST API            | Disabling the required compliance/TEE status checks, signed commits, force-push protection, deletion protection, or admin-bypass enforcement. PR reviews are not the trust root; the TEE First Principles status check is. |
| `sbom`                   | Syft                       | Drift between locked and produced dependency tree; provides SBOM digest for the predicate                        |
| `vuln-scan`              | OSV-Scanner against SBOM   | Shipping a HIGH/CRITICAL CVE in any transitive dependency                                                        |

## How the rules are pinned

The build pipeline computes:

```
compliance_rules_digest = sha256(
  cat $(find .compliance -type f \
    \( -name '*.sh' -o -name '*.mjs' -o -name '*.yml' -o -name '*.json' \) \
    -not -path '*/node_modules/*' \
    | sort)
)
```

This digest is included in the in-toto compliance predicate signed with
`cosign attest`. Verifiers can pin a known-good digest with the
`--pinned-rules-digest` flag on the standalone verifier (see
`auth-broker-tee/verifier/README.md`). Any subsequent build that uses a
weakened rule set produces a different digest, which the verifier will
flag.

When *intentionally* tightening or expanding rules:

1. Modify the relevant file under `.compliance/`.
2. Run `bash .compliance/run.sh` locally to confirm it still passes against
   `src/`.
3. Open a PR. The PR run reports the new digest in its compliance summary.
4. After merge, communicate the new digest in the release notes so external
   verifiers know to update their pin.

## How to add a new rule

1. **Semgrep rules**: append to `semgrep.yml`. Each rule must include a
   `message` block explaining the threat it defends against. Test locally:
   ```bash
   semgrep --config .compliance/semgrep.yml --error src/
   ```
2. **AST checkers**: add a new `.compliance/check-<name>.mjs` script that
   prints JSON to stdout and exits 0 on pass / non-zero on fail. Wire it
   into `run.sh` next to the existing AST checks.
3. **Allowlists**: edit the corresponding JSON file and bump it via PR.

## How to add a new TEE-side dependency

This is intentionally inconvenient -- every dep is an audit point.

1. Add the package to `package.json` and `package-lock.json` in the repo
   root (the TEE image's `npm ci` source).
2. Add the import specifier to `forbidden-imports.json#external_npm`.
3. Add the import to whichever file actually uses it.
4. PR. The compliance check will see it pass; the SBOM step will pick it
   up; OSV-Scanner will gate on its CVE history.

If the new dep would require importing something on the
`_explicitly_forbidden_even_if_added_to_allowlist` list (e.g.
`child_process`), the answer is **no** -- find another way. That list is
the architectural commitment this codebase makes to the TEE trust model.

## How to add a new Secret Manager secret

1. Add the secret to GCP Secret Manager (out-of-band).
2. Add a `data "google_secret_manager_secret"` block to
   [`terraform/main.tf`](../terraform/main.tf) and append it to
   `locals.secrets_needing_read`.
3. Add the env-var-name -> secret-name mapping to the `SECRETS` object in
   [`src/server.js`](../src/server.js).
4. Add the same mapping to `secrets-allowlist.json` in this directory.
5. PR. The `check-secrets` checker will pass once all three places agree.

## How to add a new HTTP route

1. Add the case to the `switch (url.pathname)` block in
   [`src/server.js`](../src/server.js) and the corresponding handler.
2. Add the path string to `route-allowlist.json#_main_server_routes` (or
   `_health_server_routes` if it lives on the health server).
3. PR. The `check-routes` checker will pass once both agree.

## What this directory is *not* for

- Runtime configuration. Nothing in here is read at TEE runtime.
- TLS certs, Secret Manager values, or any production data.
- Per-deploy variables. Anything that changes per-environment lives in
  Terraform variables.

The contents of `.compliance/` are part of the source-code surface that
defines what "an honest auth-broker-tee build" means. Treat changes here
with the same review intensity as changes to `src/`.

## Local development

```bash
cd auth-broker-tee
npm ci --prefix .compliance --ignore-scripts
bash .compliance/run.sh
```

In local dev the `branch-protection` check is skipped (no GITHUB_TOKEN)
and SBOM/vuln-scan are skipped if Syft / OSV-Scanner are not on PATH.
The CI workflow installs both unconditionally and runs in `STRICT=true`
mode where any skipped check fails the build.

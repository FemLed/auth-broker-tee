# Operator-Authorized Genesis Runbook (auth-broker-tee)

This is the **first-class, repeatable** procedure for a broken-continuity
re-genesis of `auth-broker-tee`: standing up a brand-new governance lineage when
there is no predecessor to vouch for the image (e.g. the active TEE is
unrecoverably inactive, or its first-principles policy is incompatible with the
candidate). It is NOT a successor activation; see
`.cursor/rules/auth-broker-tee-governance-lineage.mdc` for the distinction.

## Trust model (why self-attest does not weaken posture)

A genesis is **self-attested** on a fresh INACTIVE candidate and is **untrusted
by default**:

- The candidate self-adjudicates (`/first-principles/adjudicate`, allowed only
  while INACTIVE). `/governance/genesis-bootstrap` accepts only an approval the
  candidate produced itself that way, attested by its own image digest, and only
  with `operator-genesis.yml`'s governance OIDC token. The running image's source
  revision must still equal the TEE-approved commit, so the self-review is bound
  to a specific GitHub-reviewed image, not arbitrary code.
- The resulting lineage is length-1, epoch-1, `femled.tee.governance.genesis.v1`
  with no predecessor link. Every relying party rejects it by default:
  - the external `verifier/` run with `--require-successor-lineage`,
  - tenants (they accept only lineages extending their previously-accepted state),
  - sibling TEEs.
- Trust is granted only by **explicit downstream re-admission** (Step 5).

The authority to *create* a genesis is gated by GCP IAM + a human GitHub
Environment approval; the authority to *trust* one is an explicit, auditable
downstream opt-in. The active-TEE PR/push review path and the successor flow are
unchanged (every genesis relaxation is `status === INACTIVE`-only).

## One-time operator prerequisites

- A GitHub Environment named **`genesis`** (repo Settings -> Environments) with
  **required reviewers**. Without it, `genesis-build.yml` runs unguarded.
- `gh-actions-publisher@prod-femled-couple-router.iam.gserviceaccount.com` can
  sign with the Cosign KMS key (already granted) and write Artifact Registry.
- `SUCCESSOR_ACTIVATION_SERVICE_ACCOUNT` (used by `operator-genesis.yml`) can set
  IAM on the broker secrets, the `auth-broker-acme-renewer` KMS key, and the bucket
  holding the TLS mint ledger (so the candidate reconciler can open the candidate
  window). There is no governance KMS key: the genesis certificate is signed with
  a key generated in the candidate's enclave.

## Steps

1. **Build + sign the genesis image (human-approved).** Run
   `genesis-build.yml` (`source_revision` = the master commit to genesis from,
   `operator_statement` containing `operator-authorized re-genesis`). Approve the
   `genesis` Environment when prompted. Capture the printed image digest `D`.
   - Rollback: none needed; nothing is deployed. Delete the unused tag if desired.

2. **Genesis the candidate.** Dispatch `operator-genesis.yml` on the same ref,
   with `image_digest=D` and `source_revision` = the same commit. It opens the
   candidate WIF window (`reconcile-candidate-resource-iam.mjs`
   + the project-role reconciler), provisions a fresh INACTIVE TDX VM as replica
   slot a (`auth-broker-tee-a-<D12>`), self-adjudicates, genesis-bootstraps to
   active/epoch-1 and verifies. It then provisions replica slot b
   (`auth-broker-tee-b-<D12>`, the custodian) and waits until slot a's manifest
   names it as custodian.
   - On failure it auto-revokes the candidate window and deletes both VMs.
   - Rollback: re-run after fixing; the failure-cleanup keeps re-dispatch unblocked.

3. **Confirm health.** Slot a should report `status: active`, `epoch: 1`, the
   expected image digest and `replica: {role: "primary", peer: {role:
   "custodian"}}` at `/.well-known/femled-tee-governance.json`.

4. **Address cutover.** `oauth-tee.femled.ai` names the reserved address
   `auth-broker-tee-oauth-ip`; move it to slot a:
   ```
   bash scripts/move-reserved-ip.sh --to auth-broker-tee-a-<D12> --to-zone us-west1-b --expect-digest <D>
   ```
   The script refuses unless slot a answers as an active primary on `D`.
   - Rollback: move the address back to the prior VM.

5. **Downstream re-admission (the real trust boundary).** A genesis is not trusted
   until each relying party explicitly re-admits the new lineage:
   - **Tenants:** issue fresh `deploy_target_admission` / tenant admission envelopes
     against the new lineage (the broker repo intentionally holds no tenant project
     IDs; this is a per-tenant action in the tenant's own project). Old admissions
     bound to the prior lineage are discarded.
   - **External verifier:** for replacement verification run
     `./verifier --require-successor-lineage` (rejects a fresh genesis) until the
     new genesis is deliberately accepted, then pin the new
     `--pinned-governance-lineage-digest` for steady-state monitoring.
   - **authoritative-dns-tee:** add `D` to `EXTERNAL_TEE_RENEWERS` (auth-broker-tee
     entry, `acceptedCallerImageDigests`) so the new TEE can mint its TLS cert via
     DNS-01. This is an authoritative-dns-tee image roll + 3-of-4 quorum.

6. **Promote + revoke the candidate window.** Once steady-state, run:
   ```
   scripts/promote-genesis.sh --image-digest <D> --retire-digest <old-active-digest>
   ```
   This revokes the retired image's WIF access, repoints
   `FIRST_PRINCIPLES_TEE_EXPECTED_IMAGE_DIGEST` to `D`, unsets the bootstrap-bypass
   repo variables, and updates the bookkeeping tfvars. The new digest keeps its
   (now-active) bindings. Then decommission the old VM.

## Repeatability

The flow is re-runnable: replica VM names are keyed by slot and image digest; a
failed `operator-genesis.yml` run revokes IAM and deletes its VMs in the
failure-cleanup step. If a run was interrupted (not failure-cleaned), delete the
stale replica VMs and re-run `reconcile-candidate-resource-iam.mjs --operation
revoke --genesis` for that digest before re-dispatching.

## Losing a replica (not a genesis)

A replica that restarts is re-keyed by its peer and needs nothing. A replica
whose VM is gone for good is replaced without breaking continuity:

- **Custodian lost:** delete its VM, then run `replica-enroll.yml` for its slot.
- **Primary lost:** run `replica-failover.yml` for the custodian's slot. It
  stops the lost primary, promotes the custodian once it has heard nothing from
  the primary for three minutes, and moves the reserved address. Then delete
  the lost primary's VM and run `replica-enroll.yml` for its slot.
- **Both lost:** the lineage is gone. Re-genesis as above.

The failover and enrollment workflows need `SUCCESSOR_ACTIVATION_SERVICE_ACCOUNT`
to create instances and move access configs, and the `auth-broker-tee-allow-replica`
firewall rule (tcp:8080, `terraform/main.tf`) for the promotion request.

# How FemLed Protects Your Identity

You are considering a service that requires access to your Google Calendar
and Gmail. You want assurance that the people who built this service --
including FemLed's own employees -- cannot learn who you are.

This document explains the problem, the solution, and how you or your
security team can independently verify everything.

## The Problem

FemLed's AI coaching requires access to your Google Calendar and Gmail.
To obtain that access, you sign in with Google through an industry-standard
OAuth flow. During this flow, Google returns authentication tokens that
identify your account.

Normally, the service that processes this OAuth flow sees your email
address. This is how virtually every "Sign in with Google" implementation
works. The service always receives your real email.

For a service like FemLed -- which is deeply personal and serves clients
who are extremely sensitive about their privacy -- this is unacceptable.
If FemLed's infrastructure were breached, or if a FemLed employee acted
maliciously, the identities of every couple using the service could be
exposed.

## The Solution

FemLed's OAuth broker runs inside
[Google Cloud Confidential Space](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview),
a hardware-sealed environment powered by AMD SEV memory encryption.

Confidential Space is not a software policy or a corporate promise. It is
a physical property of the hardware. The AMD processor encrypts the
broker's memory with keys that are inaccessible to the operating system,
the hypervisor, Google Cloud itself, and FemLed's operators.

Concretely, this means:

- **FemLed cannot SSH into the machine.** The Confidential Space production
  image blocks all remote access.
- **FemLed cannot read the machine's memory.** AMD SEV encrypts it at the
  hardware level. Not even the hypervisor can decrypt it.
- **FemLed cannot enable logging.** The broker's code includes a hardware-
  enforced launch policy that blocks the operator from capturing any output.
- **FemLed cannot modify the running code.** The sealed environment runs a
  specific container image. Any change to the code produces a different
  cryptographic fingerprint that is immediately detectable.
- **FemLed cannot inspect network traffic.** TLS terminates inside the
  sealed environment. The load balancer in front of it performs raw TCP
  passthrough -- it sees only encrypted bytes.

Your Google tokens pass through this sealed environment and are deposited
directly into your couple's private, isolated infrastructure. The broker
never stores your information from Google (email, calendar, etc...) and 
never logs them.

Tenant routing is dynamic but not trusted to mutable infrastructure. Public
route records may be transported through Firestore, GCS, or another operator-
controlled store, but the broker accepts them only when they contain a
TEE-signed tenant admission certificate and a tenant-key-signed route envelope.
The tenant route private key lives in the tenant's own project, preferably as a
non-exportable KMS signing key, not in FemLed's central broker project.
Verification still depends on image, rules, and governance lineage digests
rather than repository metadata or operator statements.

## What This Means For You

FemLed never learns your email address and no one at FemLed has access to 
your email or calendar. This is not a policy decision that could be reversed. 
It is enforced by hardware that FemLed does not control and cannot circumvent.

Even in a worst-case scenario -- a complete breach of FemLed's cloud
infrastructure, combined with a malicious insider with full administrative
access -- your identity remains protected. There is nothing to find.

## Don't Trust, Verify

You do not need to take FemLed's word for any of this. The entire system
is independently verifiable:

1. **The source code is public.** You are reading it right now. Have your
   security team review it and confirm that it does not log, store, or
   transmit your email address.

2. **The build is reproducible.** Anyone can clone this repository, build
   the container image, and produce the same cryptographic fingerprint.

3. **The running code is attestable.** Google's attestation service
   produces a cryptographically signed token that proves the exact code
   running inside the sealed environment. Your security team can compare
   this against the image they built themselves.

4. **Every build is signed twice.** The image digest is bound to a
   specific commit on `master`, the specific workflow file at
   [`.github/workflows/build-and-attest.yml`](.github/workflows/build-and-attest.yml),
   and an in-toto attestation predicate that records every compliance
   check's result. The pipeline produces two complementary signatures:
   - a **keyless Sigstore signature** (Fulcio cert + Rekor entry)
     bound to GitHub's OIDC identity for that workflow run -- this is
     the public, append-only transparency layer that customers and
     external watchers verify with the standalone
     [`verifier/`](verifier/) binary.
   - a **KMS-key signature** produced with a Terraform-managed Google
     Cloud KMS asymmetric key. `cloudkms.signer` on that key is granted
     **only** to the GitHub Actions service account that builds from
     `master`. This is the signature Confidential Space's launcher and
     the Workload Identity Federation condition mechanically check.

5. **When production enforcement is on**, the WIF condition refuses
   to mint Secret Manager access tokens for any image whose attestation
   token does not expose a signature whose `signature_algorithm:key_id`
   matches the value pinned in `terraform.tfvars` as
   `expected_image_signer_fingerprint`. An unsigned (or wrong-key)
   image will technically *boot* in the Confidential VM -- the
   `tee-signed-image-repos` metadata key only tells the launcher where
   to look for signatures and what to surface in the attestation
   token; it does not by itself refuse to start unsigned containers.
   The actual enforcement gate is the WIF CEL: an image whose
   signatures don't match the pinned fingerprint cannot read a single
   secret, so the broker fails at startup when `loadSecrets()` is
   called.

   The two toggles in [terraform/variables.tf](terraform/variables.tf):
   - `enforce_signed_image_at_launch` -- adds `tee-signed-image-repos`
     to the VM metadata so the launcher publishes verified
     `image_signatures` entries in the attestation token.
   - `enforce_signed_image_in_wif` -- adds the CEL clause that pins
     to `expected_image_signer_fingerprint`.

   Both ship at `false` for the bootstrap deploy and are flipped to
   `true` per the runbook in
   [SUPPLY_CHAIN_BOOTSTRAP.md](SUPPLY_CHAIN_BOOTSTRAP.md). Verify the
   live state by reading `terraform.tfvars`; if either is not `true`,
   the broker is running without the mechanical enforcement gate.

   **Honest trust trade-off.** Confidential Space cannot mechanically
   verify keyless Sigstore signatures today (its signed-image flow
   keys off fixed public-key fingerprints, not Fulcio cert SANs). So
   the launch-time enforcement layer trusts a GCP KMS key. A
   future-FemLed-operator with full GCP admin can still substitute a
   malicious image, but only by:
   - granting themselves `cloudkms.signer` on the KMS key (a
     Terraform diff and a Cloud Audit Logs entry, AND a sink-export
     event if `kms_audit_log_sink_destination` is configured to a
     non-FemLed destination per the bootstrap runbook), AND
   - committing a new image's source code and running it through the
     public CI pipeline so that a Rekor entry exists (otherwise the
     external verifier on customer cron alerts), OR
   - rotating the KMS key fingerprint pinned in `terraform.tfvars`
     (another Terraform diff).

   These signatures are artifact evidence, not governance authority. After
   trusted genesis, a replacement is accepted as FemLed's TEE only if the
   current active TEE signs a successor lineage after activation-time Gemini
   arbitration over the candidate. A future FemLed operator can still deny
   service by shutting the TEE down or breaking the substrate, but cannot make
   a fresh parallel genesis accepted as the current TEE without breaking the
   predecessor-signed lineage checks that verifiers pin.

A small Go binary at [`verifier/`](verifier/) automates the end-to-end
check (JWT signature -> Sigstore signature -> Fulcio cert SAN -> Rekor
entry -> compliance predicate). Run it from a machine you control to
continuously prove the chain is intact.

## Sealed in-enclave TLS (ACME at genesis, carried over on continuity)

The TLS private key for `oauth-tee.femled.ai` **lives only in enclave
memory**; its sole at-rest form is a **sealed TLS capsule**
([`src/tls-capsule.js`](src/tls-capsule.js)) stored in the governance
state-capsule bucket under `tls/oauth-tee.tls-capsule.v1.json`: AES-256-GCM
ciphertext whose 32-byte DEK is wrapped by the `tls-sealing` KMS key, with
decrypt IAM granted only to the WIF `principalSet` pinned to the attested
image-digest window (active image + roll candidates). Confidential Space
exposes no vTPM to workloads, so this attestation-gated KMS unwrap is the
measured-boot sealing equivalent. **Plaintext TLS keys are never written to
Secret Manager** (the old `auth-broker-tls-cert`/`-tls-key` pair is retired
along with the manual seed flow).

Boot (`bootstrapTls` in [`src/acme-renewal.js`](src/acme-renewal.js)) is
unseal-first and runs before the listener binds:

- **Lineage continuity** (successor activation, candidate VM, same-image
  restart, capsule-restored cold start): unseal the TLS capsule and carry the
  existing in-enclave cert forward -- **no Let's Encrypt order**. After
  `activation-apply` (and after a governance capsule restore), the renewer
  verifies the TLS capsule's lineage anchor (the genesis certificate's
  `payloadDigest`) matches the governance lineage.
- **Mint** only when no usable capsule exists (first genesis boot) or the
  carried cert is expired/inside the 30-day renewal window. The ACME DNS-01
  order rides authoritative-dns-tee's external-TEE-renewer trust path:
  [`src/renewer-governance-signer.js`](src/renewer-governance-signer.js)
  builds a KMS-signed envelope bound to a fresh Confidential Space
  attestation token (audience `https://ns1.femled.ai/renewer`), which the
  `/governance/routine-zone-change-renewer` route accepts for the narrow
  `_acme-challenge.oauth-tee.femled.ai.` TXT add/remove pair. The leaf
  private key is generated in-TEE and never leaves it.
- **Genesis events always mint a fresh cert**: after
  `/governance/genesis-bootstrap`, material carried over from a previous
  lineage's capsule is force-re-minted and the capsule re-sealed under the
  new lineage anchor (the capsule's GCM AAD binds the anchor, so a stale
  capsule can never silently impersonate a new lineage).

Renewals rotate **in place**: `server.setSecureContext()` is back (the
interim `compute.instances.reset` reload contract is gone, together with its
`compute.instanceAdmin.v1` IAM grant), and the capsule is re-sealed after
every rotation. A candidate VM whose cert is due first re-reads the shared
capsule and adopts a sibling's fresher cert before spending an order against
Let's Encrypt's 5/week duplicate-certificate quota. `/health` surfaces the
runtime TLS state (origin, expiry, lineage anchor, capsule seal status,
pending re-mint).

`ACME_RENEWER_ENABLED=true` and `RENEWER_KMS_SIGNER_KEY_VERSION` are baked
into the image (sealed TLS makes in-enclave minting mandatory at genesis;
there is no Secret Manager TLS pair to seed). `ACME_RENEWER_DRY_RUN` remains
the only operator toggle (allow_env_override) for staged validation of the
order round-trip; the boot path refuses to mint under dry-run.

The fingerprint is not listed in this file because any change to this
file would change the fingerprint -- a self-referential impossibility.
Instead, the live fingerprint is obtained directly from the sealed
environment's attestation token and compared against (a) a local build
and (b) the Sigstore-signed digest in Rekor.

**For the complete technical verification walkthrough, see
[VERIFICATION.md](VERIFICATION.md). For the supply-chain trust model
specifically, see Step 4 and Step 5 there, and the build pipeline at
[.github/workflows/build-and-attest.yml](.github/workflows/build-and-attest.yml).**

## Governance State Persistence

The TEE's governance state -- lineage, epoch, accepted tenant route
policy, latest preapproval / successor / retirement certificates -- now
survives a cold start without operator intervention. The mechanism has
two parts, both gated by the same WIF attestation principal that already
controls Secret Manager and the ACME renewer signer:

1. **Governance signing key in Cloud KMS.** When the VM is launched with
   `tee-env-GOVERNANCE_KMS_SIGNER_KEY_VERSION` (provisioned by
   [`terraform/governance-state-capsule.tf`](terraform/governance-state-capsule.tf)),
   [`src/kms-governance-key.js`](src/kms-governance-key.js) replaces the
   legacy in-memory ed25519 signer with a Cloud KMS asymmetric ECDSA
   P-256 key whose `cloudkms.signerVerifier` role is bound only to the
   federated principal that the running image digest attests to. The
   private key never leaves KMS and is not extractable; the same image
   restarting on a new VM still mints the same `governancePublicKeyPem`
   and `governanceKeyId`. The activation X25519 key stays in process
   memory because successor handoffs always negotiate a fresh key pair
   on both sides.

2. **State capsules in GCS.** After every mutation that issues a new
   lineage certificate or updates `transferredState.routePolicy`, the
   running TEE seals the persistable subset of state into a capsule
   with [`src/state-capsule.js`](src/state-capsule.js) and writes it to
   the bucket provisioned by Terraform via
   [`src/capsule-store.js`](src/capsule-store.js). The capsule's AAD
   binds (image digest, KMS key version, governance public key digest,
   lineage digest, epoch, transferredState digest, status, project ID,
   capsule serial). The capsule body is AES-256-GCM encrypted under a
   per-capsule data key derived (via HKDF) from a KMS-produced witness
   signature over the AAD bytes, so the same image digest is required
   to both produce the witness and re-derive the data key on restore.
   `capsules/latest-pointer.json` names the most recent capsule and is
   updated in place.

On cold start [`initializeGovernanceAsync`](src/governance-state.js)
fetches the KMS public key, reads the pointer, fetches the capsule,
verifies the AAD digest + KMS witness signature + AES-GCM auth tag,
checks that the lineage tail's `signingKeyId` equals the
KMS-bound `governanceKeyId`, re-verifies the lineage tail envelope under
the KMS public key, then restores `status=active` with the recovered
lineage, epoch, and tenant route policy. Any integrity gate failure
falls back to `inactive` and surfaces in logs; recovery from that point
is the standard genesis-bootstrap path against a trusted-reviewer TEE.

The bucket itself is untrusted storage. Trust is rooted entirely in the
KMS attestation policy plus the application-layer AAD + signature + auth
tag binding. The bucket has versioning enabled so an operator can roll a
botched restore back by writing an older capsule digest into the
pointer object.

## Lineage Extension Example

This documentation-only marker verifies that the active self-governing TEE can approve, sign, and activate a benign successor without changing runtime behavior.
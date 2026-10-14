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
a hardware-sealed environment powered by Intel TDX memory encryption.

Confidential Space is not a software policy or a corporate promise. It is
a physical property of the hardware. The Intel processor encrypts the
broker's memory with keys that are inaccessible to the operating system,
the hypervisor, Google Cloud itself, and FemLed's operators.

Concretely, this means:

- **FemLed cannot SSH into the machine.** The Confidential Space production
  image blocks all remote access.
- **FemLed cannot read the machine's memory.** Intel TDX encrypts it at the
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

## Ephemeral in-enclave TLS (minted fresh every boot, never persisted)

The TLS private key for `oauth-tee.femled.ai` **lives only in enclave
memory** and has **no at-rest form at all**. It is minted fresh in-enclave on
every cold boot and rotated in place on renewal; nothing is sealed to KMS or
written to GCS, Secret Manager, or disk.

**Why not seal it?** Confidential Space exposes no vTPM or hardware sealing key
to workloads, so any at-rest form of the key must be unwrappable by some Cloud
KMS key -- and a GCP project/org IAM owner can self-grant decrypt on any key in
their project. A sealed TLS capsule would therefore let a malicious operator
recover the live private key and silently intercept the OAuth flow, defeating
the anonymity guarantee. Skipping persistence entirely removes that ciphertext:
there is nothing for an owner to decrypt. This makes TLS confidentiality
against a hostile owner a **prevented** property, not merely an audited one.
(The previous `tls-sealing` KMS key and `tls/…tls-capsule…` object are
retired.)

Boot (`bootstrapTls` in [`src/acme-renewal.js`](src/acme-renewal.js)) runs
before the listener binds and **always mints**: there is no capsule to carry
over. The ACME DNS-01 order rides authoritative-dns-tee's external-TEE-renewer
trust path -- [`src/renewer-governance-signer.js`](src/renewer-governance-signer.js)
builds a KMS-signed envelope bound to a fresh Confidential Space attestation
token (audience `https://ns1.femled.ai/renewer`), which the
`/governance/routine-zone-change-renewer` route accepts for the narrow
`_acme-challenge.oauth-tee.femled.ai.` TXT add/remove pair. The leaf private
key is generated in-TEE and never leaves it. Renewals rotate **in place** via
`server.setSecureContext()` (no VM reset). `/health` surfaces the runtime TLS
state (expiry, last rotation) and the mint ledger.

**Trade-offs of ephemerality (accepted):**

- Every cold boot consumes a Let's Encrypt issuance. LE allows 5 certs per
  exact identifier set per 7 days (refilling ~1 per 34h). Routine maintenance
  reboots are rare, so this is comfortable; the risk is a reboot/crash loop.
- A non-secret mint ledger ([`src/tls-mint-log.js`](src/tls-mint-log.js))
  records mint **timestamps only** (never key material) in the capsule bucket
  so a boot in an already-exhausted week fails fast instead of hammering LE.
  Tampering with it only affects availability (already a non-goal), never
  confidentiality.
- Boot now depends on the authoritative-dns-tee quorum being reachable to
  satisfy DNS-01, and adds ACME latency before the listener can serve.

`ACME_RENEWER_ENABLED=true` and `RENEWER_KMS_SIGNER_KEY_VERSION` are baked into
the image (in-enclave minting is mandatory; there is no Secret Manager TLS pair
to seed). `ACME_RENEWER_DRY_RUN` remains the only operator toggle
(allow_env_override) for staged validation of the order round-trip; the boot
path refuses to mint under dry-run.

The fingerprint is not listed in this file because any change to this
file would change the fingerprint -- a self-referential impossibility.
Instead, the live fingerprint is obtained directly from the sealed
environment's attestation token and compared against (a) a local build
and (b) the Sigstore-signed digest in Rekor.

**For the complete technical verification walkthrough, see
[VERIFICATION.md](VERIFICATION.md). For the supply-chain trust model
specifically, see Step 4 and Step 5 there, and the build pipeline at
[.github/workflows/build-and-attest.yml](.github/workflows/build-and-attest.yml).**

## Governance Key Custody

The governance signing key is an Ed25519 key generated in enclave memory when
the broker boots ([`src/governance-crypto.js`](src/governance-crypto.js)). It
has no at-rest form: it is never written to disk, Cloud Storage, Secret
Manager or Cloud KMS, so nobody who administers the GCP project holds a key
that can sign for the broker's lineage. In production the broker refuses to
establish governance on key material held anywhere else
([`src/governance-state.js`](src/governance-state.js)).

Successor activation hands governance to a new image without the key ever
leaving an enclave: the predecessor signs a successor certificate naming the
candidate's own in-enclave key, and encrypts the transferred state (lineage,
epoch, accepted tenant route policy) to the candidate's attested X25519
activation key. Before it does, the candidate proves it holds those keys
(`/governance/activation-readiness`): a statement signed with its governance
key, plus a Confidential Space token, under an audience `/attestation` never
requests, whose nonce the candidate computed over its own key ids. Offering
the predecessor someone else's keys therefore fails. A handoff that stops
halfway is finished by a late finalize, or unwound by the candidate's signed
decline or, once the successor certificate has expired, by an abort; a
predecessor that has seen the successor's proof never aborts
(`successor-recovery.yml` runs either from a failed run's evidence).

Two replicas of the same image keep the broker alive through a restart
([`src/governance-replica-custody.js`](src/governance-replica-custody.js)).
The primary serves; the custodian holds the same key and a current copy of
the state, mints no certificate and serves no broker route. A replica that
restarts comes back `inactive` and asks its peer for custody over the private
network. The peer seals the key to the restarted replica's activation key only
after a Confidential Space attestation proves that the replica runs the same
image, in this project, as the broker's service account, and that it holds
that activation key: the attestation's nonce is computed inside the enclave
over its own key ids, in answer to a single-use challenge. The primary releases
no governance change (a signed certificate, a status change) until the
custodian has acknowledged it, and reverts any change it did not, so the
surviving replica always holds everything that was released. Launch metadata
only tells a replica where its peer is. When the primary is lost, an operator
runs `replica-failover.yml`: it stops the lost primary, and the custodian
accepts promotion only after three minutes without a heartbeat from it. The
operator then enrolls a replacement (`replica-enroll.yml`).

The price is availability. Losing both replicas loses every copy of the key,
which means an operator-authorized re-genesis plus an explicit re-admission by
every relying party ([GENESIS.md](GENESIS.md)).

Earlier images signed governance with a Cloud KMS key and persisted state in
GCS capsules. Both were removed: anyone administering the project could use
the KMS key directly to sign as the broker, and the capsules' data key was
derivable from fields stored in the capsule itself.

## Lineage Extension Example

This documentation-only marker verifies that the active self-governing TEE can approve, sign, and activate a benign successor without changing runtime behavior.
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
never stores them, never logs them, and never even requests your email
address from Google.

## What This Means For You

FemLed never learns your email address. This is not a policy decision that
could be reversed. It is enforced by hardware that FemLed does not control
and cannot circumvent.

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

The fingerprint is not listed in this file because any change to this
file would change the fingerprint -- a self-referential impossibility.
Instead, the live fingerprint is obtained directly from the sealed
environment's attestation token and compared against a local build.

**For the complete technical verification walkthrough, see
[VERIFICATION.md](VERIFICATION.md).**

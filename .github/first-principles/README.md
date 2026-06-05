# TEE First Principles Bootstrap

Do not put a First Principles signing private key in the same GCP project that
runs the TEE VM. A project owner could grant themselves access to the key or
replace its Secret Manager version, which would make the GCP owner part of the
trust root.

The First Principles trust root is instead the Google Confidential Space
attestation token bound to each canonical adjudication or policy payload. The
TEE asks the Confidential Space launcher for an attestation token whose
`eat_nonce` is `sha256:<canonical-payload-hash>`. Verifiers check Google's
signature, the expected image digest, debug-disabled claims, and the nonce
binding.

Bootstrap steps:

1. Deploy only an already-audited `auth-broker-tee` image whose digest is known.
2. Set the GitHub Actions repository variable
   `FIRST_PRINCIPLES_TEE_EXPECTED_IMAGE_DIGEST` to that digest.
3. Set the GitHub Actions repository variable
   `FIRST_PRINCIPLES_EXPECTED_PROMPT_DIGEST` to the digest exported by
   `src/first-principles-review.js`.
4. In each tenant project, pin the same image digest in
   `TEE_EXPECTED_IMAGE_DIGEST`.
5. In each tenant project, pin the same prompt digest in
   `TEE_EXPECTED_FIRST_PRINCIPLES_PROMPT_DIGEST`.
6. Verify `https://oauth-tee.femled.ai/.well-known/femled-tee-policy.json`.
   Its `attestationToken` must be a valid Google Confidential Space token whose
   `eat_nonce` matches the policy payload digest and whose image digest matches
   the tenant and GitHub pins.

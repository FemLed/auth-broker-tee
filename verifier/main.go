// Verifier for the auth-broker-tee Sigstore + Confidential Space
// attestation chain.
//
// What it does, in order:
//
//  1. Fetches a fresh attestation JWT from the live TEE's /attestation
//     endpoint, with a caller-supplied nonce so we know the token is not
//     replayed from a snapshot.
//  2. Verifies the JWT signature against Google's Confidential Space JWKS
//     and asserts the standard Confidential Space claims (`swname`,
//     `dbgstat`, project_id, audience, eat_nonce).
//  3. Extracts the running image digest from the attestation token.
//  4. Shells out to `cosign verify` to confirm the image was signed by the
//     expected GitHub Actions workflow (Fulcio cert SAN matches
//     --expected-workflow-ref). The Sigstore TUF root and Rekor lookup are
//     handled by cosign so this verifier never has to embed Sigstore's
//     trust root itself.
//  5. Shells out to `cosign verify-attestation` to fetch and verify the
//     in-toto compliance predicate also signed by the same workflow,
//     parses it, and asserts:
//       - overall_status == "passed"
//       - every individual check is "passed" or "skipped" (with a flag
//         to fail-on-skip for high-assurance verifiers)
//       - if --pinned-rules-digest is supplied, the predicate's
//         compliance_rules_digest matches exactly
//
// Exit codes:
//   0  -- every check passed
//   1  -- attestation chain failed at some step (details on stderr/stdout)
//   2  -- usage / configuration error (cosign missing, bad flags, etc.)
//
// Why a Go binary that shells out to cosign rather than a pure-Go
// implementation: cosign is the official, audited Sigstore CLI. Reusing
// it for the cryptographic heavy lifting means this verifier's bug
// surface is small and understandable in one sitting. The trade-off is
// requiring `cosign` on PATH; for an ops tool a non-FemLed party runs
// from cron, that is acceptable.

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultJwksDiscoveryURL = "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"
	defaultRekorURL         = "https://rekor.sigstore.dev"
	defaultFulcioURL        = "https://fulcio.sigstore.dev"
	defaultOIDCIssuer       = "https://token.actions.githubusercontent.com"
	expectedSWName          = "CONFIDENTIAL_SPACE"
	expectedDbgStat         = "disabled-since-boot"
	expectedAudience        = "https://oauth-tee.femled.ai"
)

type config struct {
	teeURL                         string
	expectedRepo                   string
	expectedWorkflow               string
	expectedBranch                 string
	expectedProjectID              string
	expectedBrokerSA               string
	expectedImageRepoRegexp        string
	allowedEnvOverrideKeys         []string
	pinnedRulesDigest              string
	pinnedImageDigest              string
	pinnedGovernanceLineageDigest  string
	pinnedPredecessorLineageDigest string
	requireSuccessorLineage        bool
	minGovernanceEpoch             int
	jwksDiscoveryURL               string
	rekorURL                       string
	oidcIssuer                     string
	cosignBin                      string
	timeout                        time.Duration
	verbose                        bool
}

// expectedComplianceChecks lists every check that MUST appear in the
// in-toto predicate's `results` map AND must have status == "passed".
// Anything missing or with any other status fails verification. There is
// no tolerant mode: a CI-signed predicate missing checks is a hard failure.
//
// Mirrors the keys written by .compliance/run.sh's summary aggregator.
var expectedComplianceChecks = []string{
	"semgrep",
	"check_routes",
	"check_secrets",
	"check_imports",
	"check_route_integrity",
	"checker_self_tests",
	"branch_protection",
	"sbom",
	"vuln_scan",
}

// defaultAllowedEnvOverrideKeys mirrors the `allow_env_override` LABEL
// in the Dockerfile -- the only env-vars Confidential Space will let
// the workload operator inject at launch. Anything else in
// `submods.container.env_override` is a sign of operator tampering.
var defaultAllowedEnvOverrideKeys = []string{
	"GCP_PROJECT_ID",
	"GCP_PROJECT_NUMBER",
	"REDIRECT_URI",
	"GOOGLE_SCOPES",
	"AUTH_BROKER_ROUTE_FIRESTORE_COLLECTION",
	"GOVERNANCE_KMS_SIGNER_KEY_VERSION",
	"CAPSULE_BUCKET",
}

func main() {
	cfg := parseFlags()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	report := &verifyReport{}

	if err := run(ctx, cfg, report); err != nil {
		report.Error = err.Error()
		printReport(report, cfg.verbose)
		os.Exit(1)
	}

	report.Status = "passed"
	printReport(report, cfg.verbose)
}

func run(ctx context.Context, cfg *config, r *verifyReport) error {
	// 1. Sanity-check that cosign is on PATH before doing any network IO.
	if _, err := exec.LookPath(cfg.cosignBin); err != nil {
		fmt.Fprintf(os.Stderr, "cosign not found on PATH (looked for %q). Install from https://docs.sigstore.dev/cosign/installation/.\n", cfg.cosignBin)
		os.Exit(2)
	}

	// 2. Fetch attestation JWT with a fresh nonce.
	nonce, err := randomNonce(16)
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	r.Nonce = nonce

	tokenStr, err := fetchAttestationToken(ctx, cfg.teeURL, nonce)
	if err != nil {
		return fmt.Errorf("fetch attestation token: %w", err)
	}

	// 3. Verify JWT.
	claims, err := verifyAttestationJWT(ctx, cfg.jwksDiscoveryURL, tokenStr, nonce, cfg.expectedProjectID)
	if err != nil {
		return fmt.Errorf("verify attestation JWT: %w", err)
	}
	r.AttestationClaims = redactedClaims(claims)

	// 3b. Strict runtime claim assertions (operator-tampering detection).
	if err := validateRuntimeClaims(claims, cfg, r); err != nil {
		return fmt.Errorf("runtime claims: %w", err)
	}

	// 4. Extract image digest + image reference from the attestation.
	imageRef, imageDigest, err := extractImageReference(claims)
	if err != nil {
		return fmt.Errorf("extract image reference: %w", err)
	}
	r.ImageReference = imageRef
	r.ImageDigest = imageDigest

	// 4b. Image reference must match the expected repo regex (defends
	// against the operator quietly retargeting the broker to a different
	// AR repo even if everything else verifies).
	if cfg.expectedImageRepoRegexp != "" {
		repoRe, err := regexp.Compile(cfg.expectedImageRepoRegexp)
		if err != nil {
			return fmt.Errorf("compile expected-image-repo-regexp: %w", err)
		}
		if !repoRe.MatchString(imageRef) {
			return fmt.Errorf("image_reference %q does not match expected repo regexp %q", imageRef, cfg.expectedImageRepoRegexp)
		}
	}

	if cfg.pinnedImageDigest != "" && cfg.pinnedImageDigest != imageDigest {
		return fmt.Errorf("image digest mismatch: TEE is running %s but expected %s", imageDigest, cfg.pinnedImageDigest)
	}

	gov, err := fetchGovernanceManifest(ctx, cfg.teeURL)
	if err != nil {
		return fmt.Errorf("fetch governance manifest: %w", err)
	}
	if err := validateGovernanceManifest(ctx, cfg, gov, imageDigest, r); err != nil {
		return fmt.Errorf("governance manifest: %w", err)
	}

	// 5. Cosign verify -- signature on the image.
	if err := cosignVerifySignature(ctx, cfg, imageRef, imageDigest); err != nil {
		return fmt.Errorf("cosign verify (signature): %w", err)
	}
	r.SignatureVerified = true

	// 6. Cosign verify-attestation -- fetch + verify the compliance predicate.
	predicate, err := cosignVerifyAttestation(ctx, cfg, imageRef, imageDigest)
	if err != nil {
		return fmt.Errorf("cosign verify-attestation: %w", err)
	}
	r.CompliancePredicate = predicate

	// 7. Validate predicate contents.
	if err := validatePredicate(predicate, cfg, r); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------------
// Flag parsing
// ---------------------------------------------------------------------------

func parseFlags() *config {
	cfg := &config{}
	flag.StringVar(&cfg.teeURL, "tee-url", "https://oauth-tee.femled.ai", "Base URL of the TEE to verify (must expose /attestation)")
	flag.StringVar(&cfg.expectedRepo, "expected-repo", "FemLed/auth-broker-tee", "Expected GitHub repository owning the build workflow")
	flag.StringVar(&cfg.expectedWorkflow, "expected-workflow", ".github/workflows/build-and-attest.yml", "Workflow path within the repo that signs builds")
	flag.StringVar(&cfg.expectedBranch, "expected-branch", "refs/heads/master", "Git ref the workflow must run on for signatures to be honored")
	flag.StringVar(&cfg.expectedProjectID, "expected-project-id", "prod-femled-couple-router", "GCP project ID the TEE must be running in (per attestation)")
	flag.StringVar(&cfg.pinnedRulesDigest, "pinned-rules-digest", "", "If set, predicate's compliance_rules_digest MUST equal this value (recommended after first verification)")
	flag.StringVar(&cfg.pinnedImageDigest, "pinned-image-digest", "", "If set, the running image digest MUST equal this value (use to detect any image rotation)")
	flag.StringVar(&cfg.pinnedGovernanceLineageDigest, "pinned-governance-lineage-digest", "", "If set, governance manifest lineageDigest MUST equal this value")
	flag.StringVar(&cfg.pinnedPredecessorLineageDigest, "pinned-predecessor-lineage-digest", "", "If set, the running lineage must extend this predecessor lineage digest by exactly one successor certificate")
	flag.BoolVar(&cfg.requireSuccessorLineage, "require-successor-lineage", false, "Reject fresh length-1 genesis lineage; use for replacement verification after bootstrap")
	flag.IntVar(&cfg.minGovernanceEpoch, "min-governance-epoch", 0, "If >0, governance epoch must be at least this value")
	flag.StringVar(&cfg.expectedBrokerSA, "expected-broker-sa", "auth-broker-tee@prod-femled-couple-router.iam.gserviceaccount.com", "Service account email that MUST appear in `google_service_accounts` claim")
	flag.StringVar(&cfg.expectedImageRepoRegexp, "expected-image-repo-regexp", `^us-west1-docker\.pkg\.dev/prod-femled-couple-router/auth-broker/auth-broker-tee(:|@)`, "Regexp the running image_reference MUST match")
	envOverrideCSV := flag.String("allowed-env-override-keys", strings.Join(defaultAllowedEnvOverrideKeys, ","), "Comma-separated env-var keys allowed in submods.container.env_override (mirrors Dockerfile allow_env_override). Any other key is treated as operator tampering.")
	flag.StringVar(&cfg.jwksDiscoveryURL, "jwks-discovery-url", defaultJwksDiscoveryURL, "OIDC discovery URL for Confidential Space JWKS")
	flag.StringVar(&cfg.rekorURL, "rekor-url", defaultRekorURL, "Rekor base URL (cosign uses this implicitly)")
	flag.StringVar(&cfg.oidcIssuer, "oidc-issuer", defaultOIDCIssuer, "Expected OIDC issuer for the Sigstore signing identity")
	flag.StringVar(&cfg.cosignBin, "cosign", "cosign", "Path to the cosign binary")
	flag.DurationVar(&cfg.timeout, "timeout", 90*time.Second, "Overall timeout for verification")
	flag.BoolVar(&cfg.verbose, "verbose", false, "Print full predicate to stdout on success")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExit codes: 0=verified, 1=verification failed, 2=usage/config error.\n")
	}
	flag.Parse()

	if cfg.teeURL == "" || cfg.expectedRepo == "" || cfg.expectedWorkflow == "" || cfg.expectedBranch == "" {
		fmt.Fprintln(os.Stderr, "tee-url / expected-repo / expected-workflow / expected-branch are required")
		os.Exit(2)
	}
	cfg.allowedEnvOverrideKeys = splitTrim(*envOverrideCSV, ",")
	return cfg
}

func splitTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Attestation JWT fetch and verification
// ---------------------------------------------------------------------------

func randomNonce(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func fetchAttestationToken(ctx context.Context, teeURL, nonce string) (string, error) {
	u, err := url.Parse(teeURL)
	if err != nil {
		return "", err
	}
	u.Path = "/attestation"
	q := u.Query()
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/jwt")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from /attestation: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return strings.TrimSpace(string(body)), nil
}

type governanceManifest struct {
	Payload          map[string]any `json:"payload"`
	PayloadDigest    string         `json:"payloadDigest"`
	AttestationToken string         `json:"attestationToken"`
}

func fetchGovernanceManifest(ctx context.Context, teeURL string) (*governanceManifest, error) {
	u, err := url.Parse(teeURL)
	if err != nil {
		return nil, err
	}
	u.Path = "/.well-known/femled-tee-governance.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from governance manifest: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var manifest governanceManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func validateGovernanceManifest(ctx context.Context, cfg *config, manifest *governanceManifest, imageDigest string, r *verifyReport) error {
	if manifest == nil || manifest.Payload == nil || manifest.AttestationToken == "" {
		return errors.New("governance manifest missing payload or attestationToken")
	}
	payloadDigest, err := canonicalDigest(manifest.Payload)
	if err != nil {
		return err
	}
	if manifest.PayloadDigest != payloadDigest {
		return fmt.Errorf("payloadDigest mismatch: expected %s, got %s", payloadDigest, manifest.PayloadDigest)
	}
	if _, err := verifyAttestationJWT(ctx, cfg.jwksDiscoveryURL, manifest.AttestationToken, payloadDigest, cfg.expectedProjectID); err != nil {
		return fmt.Errorf("manifest attestation: %w", err)
	}
	if str(manifest.Payload["status"]) != "active" {
		return fmt.Errorf("governance status must be active, got %q", str(manifest.Payload["status"]))
	}
	if str(manifest.Payload["imageDigest"]) != imageDigest {
		return fmt.Errorf("governance imageDigest %q does not match attestation %q", str(manifest.Payload["imageDigest"]), imageDigest)
	}
	lineage, ok := manifest.Payload["lineage"].([]any)
	if !ok || len(lineage) == 0 {
		return errors.New("governance lineage missing")
	}
	lineageDigest, err := canonicalDigest(lineage)
	if err != nil {
		return err
	}
	if str(manifest.Payload["lineageDigest"]) != lineageDigest {
		return fmt.Errorf("lineageDigest mismatch: expected %s, got %s", lineageDigest, str(manifest.Payload["lineageDigest"]))
	}
	currentKeyID, currentImageDigest, currentModelPolicyDigest, currentPublicKeyPEM, currentEpoch, err := validateGovernanceLineage(lineage)
	if err != nil {
		return err
	}
	if err := validateLineageContinuityPolicy(lineage, lineageDigest, currentEpoch, cfg); err != nil {
		return err
	}
	if currentKeyID != str(manifest.Payload["governanceKeyId"]) {
		return fmt.Errorf("governanceKeyId mismatch: lineage has %s, manifest has %s", currentKeyID, str(manifest.Payload["governanceKeyId"]))
	}
	if int(num(manifest.Payload["epoch"])) != currentEpoch {
		return fmt.Errorf("governance epoch mismatch: lineage has %d, manifest has %d", currentEpoch, int(num(manifest.Payload["epoch"])))
	}
	if currentImageDigest != imageDigest {
		return fmt.Errorf("lineage current image digest %s does not match attestation %s", currentImageDigest, imageDigest)
	}
	if str(manifest.Payload["modelPolicyDigest"]) == "" || currentModelPolicyDigest == "" {
		return errors.New("governance manifest or lineage missing modelPolicyDigest")
	}
	if err := validateSelfHealingProposals(manifest.Payload, currentPublicKeyPEM); err != nil {
		return err
	}
	r.Governance = map[string]any{
		"status":                     manifest.Payload["status"],
		"epoch":                      manifest.Payload["epoch"],
		"governanceKeyId":            manifest.Payload["governanceKeyId"],
		"lineageDigest":              manifest.Payload["lineageDigest"],
		"modelPolicyDigest":          manifest.Payload["modelPolicyDigest"],
		"health":                     manifest.Payload["health"],
		"selfHealingProposalDigests": nestedAnyMap(manifest.Payload, "selfHealing", "openProposalDigests"),
	}
	return nil
}

func validateGovernanceLineage(lineage []any) (keyID string, imageDigest string, modelPolicyDigest string, publicKeyPEM string, epoch int, err error) {
	first, ok := lineage[0].(map[string]any)
	if !ok {
		return "", "", "", "", 0, errors.New("genesis envelope malformed")
	}
	genesisPayload, ok := first["payload"].(map[string]any)
	if !ok {
		return "", "", "", "", 0, errors.New("genesis payload malformed")
	}
	genesisPublicKeyPEM := str(genesisPayload["governancePublicKeyPem"])
	if err := verifyGovernanceEnvelopeMap(first, genesisPublicKeyPEM); err != nil {
		return "", "", "", "", 0, fmt.Errorf("genesis: %w", err)
	}
	if str(genesisPayload["schema"]) != "femled.tee.governance.genesis.v1" {
		return "", "", "", "", 0, fmt.Errorf("genesis schema mismatch: %s", str(genesisPayload["schema"]))
	}
	if int(num(genesisPayload["epoch"])) != 1 {
		return "", "", "", "", 0, fmt.Errorf("genesis epoch must be 1, got %d", int(num(genesisPayload["epoch"])))
	}
	if str(genesisPayload["model"]) == "" || str(genesisPayload["firstPrinciplesPromptDigest"]) == "" || str(genesisPayload["responseSchemaDigest"]) == "" || str(genesisPayload["modelPolicyDigest"]) == "" {
		return "", "", "", "", 0, errors.New("genesis missing model/prompt/schema/model-policy metadata")
	}
	currentKeyID := str(genesisPayload["governanceKeyId"])
	currentImageDigest := str(genesisPayload["imageDigest"])
	currentModelPolicyDigest := str(genesisPayload["modelPolicyDigest"])
	currentPublicKey := genesisPublicKeyPEM
	currentEpoch := int(num(genesisPayload["epoch"]))

	for i := 1; i < len(lineage); i++ {
		env, ok := lineage[i].(map[string]any)
		if !ok {
			return "", "", "", "", 0, fmt.Errorf("lineage envelope %d malformed", i)
		}
		payload, ok := env["payload"].(map[string]any)
		if !ok {
			return "", "", "", "", 0, fmt.Errorf("lineage payload %d malformed", i)
		}
		if err := verifyGovernanceEnvelopeMap(env, currentPublicKey); err != nil {
			return "", "", "", "", 0, fmt.Errorf("lineage %d: %w", i, err)
		}
		if str(payload["schema"]) != "femled.tee.governance.successor.v1" {
			return "", "", "", "", 0, fmt.Errorf("lineage %d has unexpected schema %q", i, str(payload["schema"]))
		}
		if int(num(payload["predecessorEpoch"])) != currentEpoch || int(num(payload["successorEpoch"])) != currentEpoch+1 {
			return "", "", "", "", 0, fmt.Errorf("lineage %d epoch discontinuity", i)
		}
		if str(payload["model"]) == "" || str(payload["firstPrinciplesPromptDigest"]) == "" || str(payload["responseSchemaDigest"]) == "" || str(payload["modelPolicyDigest"]) == "" {
			return "", "", "", "", 0, fmt.Errorf("lineage %d missing model/prompt/schema/model-policy metadata", i)
		}
		currentEpoch++
		currentKeyID = str(payload["successorGovernanceKeyId"])
		currentPublicKey = str(payload["successorGovernancePublicKeyPem"])
		currentImageDigest = str(payload["candidateImageDigest"])
		currentModelPolicyDigest = str(payload["modelPolicyDigest"])
	}
	return currentKeyID, currentImageDigest, currentModelPolicyDigest, currentPublicKey, currentEpoch, nil
}

func validateLineageContinuityPolicy(lineage []any, lineageDigest string, currentEpoch int, cfg *config) error {
	if cfg.pinnedGovernanceLineageDigest != "" && cfg.pinnedGovernanceLineageDigest != lineageDigest {
		return fmt.Errorf("governance lineage digest mismatch: got %s but pinned %s", lineageDigest, cfg.pinnedGovernanceLineageDigest)
	}
	if cfg.requireSuccessorLineage && len(lineage) <= 1 {
		return errors.New("fresh genesis lineage is not acceptable when successor lineage is required")
	}
	if cfg.minGovernanceEpoch > 0 && currentEpoch < cfg.minGovernanceEpoch {
		return fmt.Errorf("governance epoch %d is below minimum %d", currentEpoch, cfg.minGovernanceEpoch)
	}
	if cfg.pinnedPredecessorLineageDigest != "" {
		if len(lineage) <= 1 {
			return errors.New("predecessor lineage pin requires a successor lineage")
		}
		predecessorDigest, err := canonicalDigest(lineage[:len(lineage)-1])
		if err != nil {
			return err
		}
		if predecessorDigest != cfg.pinnedPredecessorLineageDigest {
			return fmt.Errorf("predecessor lineage digest mismatch: got %s but pinned %s", predecessorDigest, cfg.pinnedPredecessorLineageDigest)
		}
	}
	return nil
}

func validateSelfHealingProposals(payload map[string]any, currentPublicKeyPEM string) error {
	selfHealing, _ := payload["selfHealing"].(map[string]any)
	if selfHealing == nil {
		return nil
	}
	digestSet := map[string]bool{}
	if digests, ok := selfHealing["openProposalDigests"].([]any); ok {
		for _, digest := range digests {
			digestSet[str(digest)] = true
		}
	}
	proposals, _ := selfHealing["openProposals"].([]any)
	for _, item := range proposals {
		env, ok := item.(map[string]any)
		if !ok {
			return errors.New("self-healing proposal envelope malformed")
		}
		if err := verifyGovernanceEnvelopeMap(env, currentPublicKeyPEM); err != nil {
			return fmt.Errorf("self-healing proposal: %w", err)
		}
		proposalPayload, _ := env["payload"].(map[string]any)
		if str(proposalPayload["schema"]) != "femled.tee.self_healing.proposal.v1" {
			return fmt.Errorf("self-healing proposal schema mismatch: %s", str(proposalPayload["schema"]))
		}
		if !digestSet[str(env["payloadDigest"])] {
			return fmt.Errorf("self-healing proposal digest %s missing from openProposalDigests", str(env["payloadDigest"]))
		}
		if expiresAt := str(proposalPayload["expiresAt"]); expiresAt != "" {
			parsed, err := time.Parse(time.RFC3339, expiresAt)
			if err != nil {
				return fmt.Errorf("self-healing proposal expiresAt invalid: %w", err)
			}
			if time.Now().After(parsed) {
				return fmt.Errorf("self-healing proposal %s is expired", str(env["payloadDigest"]))
			}
		}
	}
	return nil
}

func verifyGovernanceEnvelopeMap(env map[string]any, publicKeyPEM string) error {
	if str(env["schema"]) != "femled.tee.governance.envelope.v1" {
		return fmt.Errorf("envelope schema mismatch: %s", str(env["schema"]))
	}
	payload, ok := env["payload"].(map[string]any)
	if !ok {
		return errors.New("payload missing")
	}
	payloadDigest, err := canonicalDigest(payload)
	if err != nil {
		return err
	}
	if str(env["payloadDigest"]) != payloadDigest {
		return fmt.Errorf("payloadDigest mismatch: expected %s, got %s", payloadDigest, str(env["payloadDigest"]))
	}
	pub, err := parseGovernancePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	if str(env["signingKeyId"]) != keyIDForGovernancePublicKey(pub) {
		return fmt.Errorf("signingKeyId mismatch: expected %s, got %s", keyIDForGovernancePublicKey(pub), str(env["signingKeyId"]))
	}
	sigObj, ok := env["signature"].(map[string]any)
	if !ok {
		return errors.New("signature missing")
	}
	sigAlg := str(sigObj["alg"])
	if sigAlg != "Ed25519" && sigAlg != "ECDSA_P256_SHA256" {
		return fmt.Errorf("signature alg must be Ed25519 or ECDSA_P256_SHA256, got %s", sigAlg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(str(sigObj["sig"]))
	if err != nil {
		return err
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		return err
	}
	// The broker labels some legacy KMS-backed signatures as "Ed25519" even
	// though the underlying key is ECDSA P-256 (see
	// kms-governance-key.js comment about Node's crypto.verify(null, ...)
	// auto-routing by key type). Be permissive here: route verification by
	// the actual key type, not the (possibly stale) alg label. New certs
	// signed by the patched broker carry the correct label.
	switch typedPub := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(typedPub, canonical, sig) {
			return errors.New("governance Ed25519 signature verification failed")
		}
	case *ecdsa.PublicKey:
		if typedPub.Curve != elliptic.P256() {
			return fmt.Errorf("governance EC public key must use P-256, got %s", typedPub.Curve.Params().Name)
		}
		digest := sha256.Sum256(canonical)
		if !ecdsa.VerifyASN1(typedPub, digest[:], sig) {
			return errors.New("governance ECDSA_P256_SHA256 signature verification failed")
		}
	default:
		return fmt.Errorf("governance public key type %T not supported", pub)
	}
	return nil
}

type csClaims struct {
	jwt.RegisteredClaims
	SWName                string                 `json:"swname"`
	DbgStat               string                 `json:"dbgstat"`
	EatNonce              any                    `json:"eat_nonce"`
	Submods               map[string]any         `json:"submods"`
	HwModel               string                 `json:"hwmodel"`
	OEMID                 any                    `json:"oemid"`
	GoogleServiceAccounts []string               `json:"google_service_accounts"`
	Extra                 map[string]interface{} `json:"-"`
}

func verifyAttestationJWT(ctx context.Context, discoveryURL, token, expectedNonce, expectedProjectID string) (*csClaims, error) {
	jwksURL, err := discoverJWKSURI(ctx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}

	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("load JWKS: %w", err)
	}

	parser := jwt.NewParser(jwt.WithExpirationRequired())
	claims := &csClaims{}
	parsedToken, err := parser.ParseWithClaims(token, claims, kf.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}
	if !parsedToken.Valid {
		return nil, errors.New("attestation JWT marked invalid by parser")
	}

	// Validate audience.
	audOK := false
	for _, a := range claims.Audience {
		if a == expectedAudience {
			audOK = true
			break
		}
	}
	if !audOK {
		return nil, fmt.Errorf("attestation audience does not include %q (got %v)", expectedAudience, claims.Audience)
	}

	// Validate Confidential Space identity claims.
	if claims.SWName != expectedSWName {
		return nil, fmt.Errorf("swname=%q, expected %q (workload is not running on Confidential Space)", claims.SWName, expectedSWName)
	}
	if claims.DbgStat != expectedDbgStat {
		return nil, fmt.Errorf("dbgstat=%q, expected %q (TEE may be in debug mode -- SSH could be possible)", claims.DbgStat, expectedDbgStat)
	}

	// Verify nonce echoed back. The attestation endpoint echoes nonces in
	// `eat_nonce`, which can be a string or an array depending on token version.
	if !nonceMatches(claims.EatNonce, expectedNonce) {
		return nil, fmt.Errorf("eat_nonce did not echo back caller-supplied nonce (replay protection failed)")
	}

	// Verify project ID via submods.gce.project_id.
	if pid := nestedString(claims.Submods, "gce", "project_id"); pid != expectedProjectID {
		return nil, fmt.Errorf("submods.gce.project_id=%q, expected %q", pid, expectedProjectID)
	}

	return claims, nil
}

func discoverJWKSURI(ctx context.Context, discoveryURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}
	var doc struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", err
	}
	if doc.JwksURI == "" {
		return "", errors.New("OIDC discovery doc missing jwks_uri")
	}
	return doc.JwksURI, nil
}

func nonceMatches(eatNonce any, expected string) bool {
	switch v := eatNonce.(type) {
	case string:
		return v == expected
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func nestedString(m map[string]any, path ...string) string {
	cur := any(m)
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return ""
}

func extractImageReference(c *csClaims) (string, string, error) {
	digest := nestedString(c.Submods, "container", "image_digest")
	ref := nestedString(c.Submods, "container", "image_reference")
	if digest == "" {
		return "", "", errors.New("submods.container.image_digest missing from attestation")
	}
	if ref == "" {
		return "", "", errors.New("submods.container.image_reference missing from attestation")
	}
	return ref, digest, nil
}

// redactedClaims returns a JSON-friendly view of the claims that omits
// nothing sensitive (the attestation token itself is intentionally
// publishable per VERIFICATION.md), but flattens the structure for
// readable output.
func redactedClaims(c *csClaims) map[string]any {
	out := map[string]any{
		"audience":                c.Audience,
		"swname":                  c.SWName,
		"dbgstat":                 c.DbgStat,
		"submods":                 c.Submods,
		"google_service_accounts": c.GoogleServiceAccounts,
	}
	if !c.ExpiresAt.IsZero() {
		out["expires_at"] = c.ExpiresAt.Format(time.RFC3339)
	}
	if !c.IssuedAt.IsZero() {
		out["issued_at"] = c.IssuedAt.Format(time.RFC3339)
	}
	return out
}

// ---------------------------------------------------------------------------
// Cosign subprocess wrappers
// ---------------------------------------------------------------------------

func certIdentityRegexp(cfg *config) string {
	// e.g. ^https://github\.com/FemLed/auth-broker-tee/\.github/workflows/build-and-attest\.yml@refs/heads/master$
	repo := regexpEscape(cfg.expectedRepo)
	wf := regexpEscape(cfg.expectedWorkflow)
	br := regexpEscape(cfg.expectedBranch)
	return fmt.Sprintf("^https://github\\.com/%s/%s@%s$", repo, wf, br)
}

func regexpEscape(s string) string {
	r := strings.NewReplacer(
		`.`, `\.`, `+`, `\+`, `*`, `\*`, `?`, `\?`, `(`, `\(`, `)`, `\)`,
		`[`, `\[`, `]`, `\]`, `{`, `\{`, `}`, `\}`, `^`, `\^`, `$`, `\$`,
		`|`, `\|`, `\`, `\\`,
	)
	return r.Replace(s)
}

func cosignVerifySignature(ctx context.Context, cfg *config, imageRef, imageDigest string) error {
	args := []string{
		"verify",
		"--certificate-identity-regexp", certIdentityRegexp(cfg),
		"--certificate-oidc-issuer", cfg.oidcIssuer,
		"--rekor-url", cfg.rekorURL,
		"--output", "json",
		joinDigest(imageRef, imageDigest),
	}
	out, err := runCosign(ctx, cfg.cosignBin, args)
	if err != nil {
		return fmt.Errorf("%w (output: %s)", err, truncate(out, 2000))
	}
	return nil
}

func cosignVerifyAttestation(ctx context.Context, cfg *config, imageRef, imageDigest string) (*compliancePredicate, error) {
	args := []string{
		"verify-attestation",
		"--certificate-identity-regexp", certIdentityRegexp(cfg),
		"--certificate-oidc-issuer", cfg.oidcIssuer,
		"--rekor-url", cfg.rekorURL,
		"--type", "https://femled.ai/attestations/auth-broker-compliance/v1",
		"--output", "json",
		joinDigest(imageRef, imageDigest),
	}
	out, err := runCosign(ctx, cfg.cosignBin, args)
	if err != nil {
		return nil, fmt.Errorf("%w (output: %s)", err, truncate(out, 2000))
	}

	// cosign verify-attestation prints one or more JSON envelopes (DSSE) on
	// stdout, one per matching attestation. Each envelope's `payload` is the
	// base64url-encoded in-toto statement. We parse each, take the first that
	// matches our expected predicate type, and return its predicate body.
	pred, err := parseAttestationPayload(out)
	if err != nil {
		return nil, fmt.Errorf("parse attestation payload: %w", err)
	}
	return pred, nil
}

func runCosign(ctx context.Context, bin string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "COSIGN_EXPERIMENTAL=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func joinDigest(ref, digest string) string {
	if i := strings.LastIndex(ref, "@"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	// ref looks like "us-west1-docker.pkg.dev/.../auth-broker-tee:latest"; we
	// drop any tag and append @<digest>.
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref + "@" + digest
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// Predicate parsing and validation
// ---------------------------------------------------------------------------

type compliancePredicate struct {
	Raw     map[string]any `json:"-"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string         `json:"predicateType"`
	Predicate     map[string]any `json:"predicate"`
}

func parseAttestationPayload(cosignOutput string) (*compliancePredicate, error) {
	// cosign verify-attestation emits a DSSE envelope per line; each envelope
	// has a `payload` field which is base64-encoded JSON of the in-toto stmt.
	dec := json.NewDecoder(strings.NewReader(cosignOutput))
	for dec.More() {
		var env struct {
			Payload string `json:"payload"`
		}
		if err := dec.Decode(&env); err != nil {
			return nil, fmt.Errorf("decode DSSE envelope: %w", err)
		}
		if env.Payload == "" {
			continue
		}
		raw, err := decodeStandardOrURLBase64(env.Payload)
		if err != nil {
			return nil, fmt.Errorf("decode payload: %w", err)
		}
		var stmt compliancePredicate
		if err := json.Unmarshal(raw, &stmt); err != nil {
			return nil, fmt.Errorf("unmarshal in-toto statement: %w", err)
		}
		if stmt.PredicateType == "https://femled.ai/attestations/auth-broker-compliance/v1" {
			if err := json.Unmarshal(raw, &stmt.Raw); err != nil {
				return nil, err
			}
			return &stmt, nil
		}
	}
	return nil, errors.New("no matching predicate of type https://femled.ai/attestations/auth-broker-compliance/v1 found in cosign output")
}

// decodeStandardOrURLBase64 tolerates both standard and URL-safe base64,
// with or without padding. cosign uses standard padded base64 today; this
// is forward-compatibility insurance.
func decodeStandardOrURLBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid standard or URL base64")
}

// validatePredicate enforces strict-by-default semantics on the in-toto
// compliance predicate signed by the GHA workflow:
//
//   - overall_status MUST equal "passed".
//   - rules digest MUST match --pinned-rules-digest if supplied.
//   - For every name in expectedComplianceChecks, the predicate's
//     `results.<name>` MUST exist and have status == "passed". There is no
//     tolerant mode: a missing check entry or a "skipped" status is a hard
//     failure (the deprecated --lax / --skip-attestation bridges were removed
//     so CI-signed evidence can never be downgraded to warnings).
//   - Any per-check status that is not exactly "passed" / "skipped" /
//     "failed" is treated as failure -- a typo'd or manipulated status
//     should never silently let a check pass.
//   - Extra checks beyond expectedComplianceChecks are tolerated (they
//     can only ADD information; their failure would have been caught by
//     overall_status).
func validatePredicate(p *compliancePredicate, cfg *config, r *verifyReport) error {
	overall, _ := p.Predicate["overall_status"].(string)
	if overall != "passed" {
		return fmt.Errorf("predicate.overall_status=%q (must be 'passed')", overall)
	}

	rulesDigest, _ := p.Predicate["compliance_rules_digest"].(string)
	r.RulesDigest = rulesDigest
	if cfg.pinnedRulesDigest != "" && cfg.pinnedRulesDigest != rulesDigest {
		return fmt.Errorf("rules digest mismatch: predicate has %s but pinned %s", rulesDigest, cfg.pinnedRulesDigest)
	}

	results, ok := p.Predicate["results"].(map[string]any)
	if !ok {
		return errors.New("predicate.results missing")
	}

	// Index discovered statuses for the expected-check loop.
	discoveredStatus := map[string]string{}
	for name, body := range results {
		bodyMap, _ := body.(map[string]any)
		status, _ := bodyMap["status"].(string)
		discoveredStatus[name] = status
		r.CheckStatuses = append(r.CheckStatuses, checkStatus{Name: name, Status: status})
	}
	sort.Slice(r.CheckStatuses, func(i, j int) bool { return r.CheckStatuses[i].Name < r.CheckStatuses[j].Name })

	for _, expected := range expectedComplianceChecks {
		status, present := discoveredStatus[expected]
		if !present {
			return fmt.Errorf("expected compliance check %q is missing from predicate.results", expected)
		}
		switch status {
		case "passed":
			// OK
		case "skipped":
			return fmt.Errorf("compliance check %q has status %q (skipped is rejected; every required check must pass)", expected, status)
		case "failed":
			return fmt.Errorf("compliance check %q failed", expected)
		case "":
			return fmt.Errorf("compliance check %q has empty status (predicate may be malformed or tampered)", expected)
		default:
			return fmt.Errorf("compliance check %q has unknown status %q (must be one of passed|skipped|failed)", expected, status)
		}
	}

	// Defense in depth: catch any EXTRA check (one we don't have in our
	// expected list because it was added after this verifier was built)
	// that the predicate marks as `failed`. The orchestrator should have
	// also flipped overall_status to "failed" in that case, but we
	// don't trust that single boolean -- a malformed orchestrator could
	// emit overall_status=passed while a per-check entry is failed.
	for name, status := range discoveredStatus {
		if status == "failed" {
			return fmt.Errorf("predicate has extra compliance check %q with status=failed (overall_status was %q, but per-check entry overrides)", name, "passed")
		}
	}

	return nil
}

// validateRuntimeClaims enforces that the running TEE has not been
// retargeted by the operator at launch time. Confidential Space's
// `submods.container.{cmd_override,env_override}` reflect anything the
// operator passed via tee-cmd / tee-env-* metadata; the workload
// service account claim reflects --service-account on the VM. Any
// drift here is an "operator changed the launch shape" signal and
// fails the verifier.
func validateRuntimeClaims(c *csClaims, cfg *config, r *verifyReport) error {
	// 1. cmd_override MUST be empty (or absent). A non-empty cmd_override
	// means tee-cmd was used to override Dockerfile's CMD, which would
	// let the operator run a different entrypoint than the one we
	// audited.
	if cmds := nestedAny(c.Submods, "container", "cmd_override"); cmds != nil {
		if arr, ok := cmds.([]any); ok && len(arr) > 0 {
			return fmt.Errorf("submods.container.cmd_override=%v (must be empty)", arr)
		}
	}

	// 2. env_override MUST contain only keys we expect. The Dockerfile's
	// `tee.launch_policy.allow_env_override` LABEL is the source of
	// truth; we mirror that allowlist here as a runtime double-check.
	if envOver := nestedAny(c.Submods, "container", "env_override"); envOver != nil {
		envMap, _ := envOver.(map[string]any)
		allowed := map[string]bool{}
		for _, k := range cfg.allowedEnvOverrideKeys {
			allowed[k] = true
		}
		for k := range envMap {
			if !allowed[k] {
				return fmt.Errorf("submods.container.env_override has unexpected key %q (allowed: %v)", k, cfg.allowedEnvOverrideKeys)
			}
		}
	}

	// 3. google_service_accounts MUST contain the expected broker SA.
	if cfg.expectedBrokerSA != "" {
		found := false
		for _, sa := range c.GoogleServiceAccounts {
			if sa == cfg.expectedBrokerSA {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("google_service_accounts claim does not include expected broker SA %q (got %v)", cfg.expectedBrokerSA, c.GoogleServiceAccounts)
		}
	}
	return nil
}

// nestedAny is a typed-any-friendly cousin of nestedString that returns
// the raw value at submods.<path> (or nil).
func nestedAny(m map[string]any, path ...string) any {
	cur := any(m)
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func nestedAnyMap(m map[string]any, path ...string) any {
	return nestedAny(m, path...)
}

func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func canonicalDigest(v any) (string, error) {
	b, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func parseGovernancePublicKey(publicKeyPEM string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("governance public key PEM decode failed")
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch k := keyAny.(type) {
	case ed25519.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("governance EC public key must use P-256, got %s", k.Curve.Params().Name)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("governance public key type %T not supported (expected Ed25519 or ECDSA P-256)", keyAny)
	}
}

func keyIDForGovernancePublicKey(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func num(v any) float64 {
	if n, ok := v.(float64); ok {
		return n
	}
	return 0
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

type checkStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type verifyReport struct {
	Status              string                 `json:"status"`
	Error               string                 `json:"error,omitempty"`
	Warnings            []string               `json:"warnings,omitempty"`
	Nonce               string                 `json:"nonce"`
	ImageReference      string                 `json:"image_reference,omitempty"`
	ImageDigest         string                 `json:"image_digest,omitempty"`
	SignatureVerified   bool                   `json:"signature_verified"`
	RulesDigest         string                 `json:"compliance_rules_digest,omitempty"`
	CheckStatuses       []checkStatus          `json:"compliance_check_statuses,omitempty"`
	Governance          map[string]any         `json:"governance,omitempty"`
	AttestationClaims   map[string]any         `json:"attestation_claims,omitempty"`
	CompliancePredicate *compliancePredicate   `json:"compliance_predicate,omitempty"`
	Extra               map[string]interface{} `json:"-"`
}

func printReport(r *verifyReport, verbose bool) {
	if !verbose && r.CompliancePredicate != nil {
		// In non-verbose mode, summarize the predicate to keep stdout small.
		r.CompliancePredicate = nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

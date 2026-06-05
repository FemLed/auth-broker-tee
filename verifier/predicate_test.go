package main

import (
	"strings"
	"testing"
)

// Builds a minimal compliancePredicate whose Predicate map is the only
// thing validatePredicate reads. Tests cover the strict-mode behavior
// the plan calls out: missing checks, unknown statuses, skipped checks.
func newPredicate(overall string, results map[string]any, rulesDigest string) *compliancePredicate {
	return &compliancePredicate{
		Predicate: map[string]any{
			"overall_status":          overall,
			"compliance_rules_digest": rulesDigest,
			"results":                 results,
		},
	}
}

func passResults() map[string]any {
	out := map[string]any{}
	for _, name := range expectedComplianceChecks {
		out[name] = map[string]any{"status": "passed"}
	}
	return out
}

func TestValidatePredicate_HappyPath(t *testing.T) {
	p := newPredicate("passed", passResults(), "sha256:abc")
	cfg := &config{}
	r := &verifyReport{}
	if err := validatePredicate(p, cfg, r); err != nil {
		t.Fatalf("happy path failed: %v", err)
	}
}

func TestValidatePredicate_OverallStatusNotPassed(t *testing.T) {
	p := newPredicate("failed", passResults(), "")
	cfg := &config{}
	r := &verifyReport{}
	if err := validatePredicate(p, cfg, r); err == nil {
		t.Fatal("expected failure when overall_status != passed")
	}
}

func TestValidatePredicate_MissingExpectedCheckStrict(t *testing.T) {
	results := passResults()
	delete(results, "checker_self_tests")
	p := newPredicate("passed", results, "")
	cfg := &config{}
	r := &verifyReport{}
	err := validatePredicate(p, cfg, r)
	if err == nil {
		t.Fatal("expected strict mode to fail when an expected check is missing")
	}
	if !strings.Contains(err.Error(), "checker_self_tests") {
		t.Fatalf("expected error to name the missing check, got: %v", err)
	}
}

func TestValidatePredicate_UnknownStatusFails(t *testing.T) {
	results := passResults()
	results["sbom"] = map[string]any{"status": "weird-typo"}
	p := newPredicate("passed", results, "")
	cfg := &config{}
	err := validatePredicate(p, cfg, &verifyReport{})
	if err == nil {
		t.Fatal("expected unknown per-check status to fail closed")
	}
}

func TestValidatePredicate_EmptyStatusFails(t *testing.T) {
	results := passResults()
	results["sbom"] = map[string]any{"status": ""}
	p := newPredicate("passed", results, "")
	err := validatePredicate(p, &config{}, &verifyReport{})
	if err == nil {
		t.Fatal("expected empty per-check status to fail closed")
	}
}

func TestValidatePredicate_SkippedFailsStrict(t *testing.T) {
	results := passResults()
	results["semgrep"] = map[string]any{"status": "skipped"}
	if err := validatePredicate(newPredicate("passed", results, ""), &config{}, &verifyReport{}); err == nil {
		t.Fatal("expected strict mode to reject skipped status")
	}
}

func TestValidatePredicate_FailedAlwaysFails(t *testing.T) {
	results := passResults()
	results["vuln_scan"] = map[string]any{"status": "failed"}
	if err := validatePredicate(newPredicate("passed", results, ""), &config{}, &verifyReport{}); err == nil {
		t.Fatal("failed status must fail")
	}
}

func TestValidatePredicate_ExtraFailedCheckCaught(t *testing.T) {
	// Defense-in-depth: an orchestrator that wrongly emits
	// overall_status=passed while a per-check entry is failed must
	// still get caught. This covers checks added after the verifier
	// was built.
	results := passResults()
	results["future_check_we_dont_know_about"] = map[string]any{"status": "failed"}
	if err := validatePredicate(newPredicate("passed", results, ""), &config{}, &verifyReport{}); err == nil {
		t.Fatal("extra failed check must fail the verifier even though overall_status=passed")
	}
}

func TestValidatePredicate_RulesDigestMismatch(t *testing.T) {
	p := newPredicate("passed", passResults(), "sha256:actual")
	cfg := &config{pinnedRulesDigest: "sha256:expected"}
	if err := validatePredicate(p, cfg, &verifyReport{}); err == nil {
		t.Fatal("expected pinned rules digest mismatch to fail")
	}
}

func TestValidateRuntimeClaims_CmdOverrideRejected(t *testing.T) {
	c := &csClaims{Submods: map[string]any{
		"container": map[string]any{"cmd_override": []any{"sh"}},
	}}
	cfg := &config{allowedEnvOverrideKeys: defaultAllowedEnvOverrideKeys, expectedBrokerSA: ""}
	if err := validateRuntimeClaims(c, cfg, &verifyReport{}); err == nil {
		t.Fatal("expected non-empty cmd_override to fail")
	}
}

func TestValidateRuntimeClaims_UnexpectedEnvOverrideRejected(t *testing.T) {
	c := &csClaims{Submods: map[string]any{
		"container": map[string]any{"env_override": map[string]any{"SECRET_INJECT": "x"}},
	}}
	cfg := &config{allowedEnvOverrideKeys: defaultAllowedEnvOverrideKeys, expectedBrokerSA: ""}
	if err := validateRuntimeClaims(c, cfg, &verifyReport{}); err == nil {
		t.Fatal("expected unexpected env_override key to fail")
	}
}

func TestValidateRuntimeClaims_MissingBrokerSARejected(t *testing.T) {
	c := &csClaims{
		Submods:               map[string]any{"container": map[string]any{}},
		GoogleServiceAccounts: []string{"some-other-sa@p.iam.gserviceaccount.com"},
	}
	cfg := &config{allowedEnvOverrideKeys: defaultAllowedEnvOverrideKeys, expectedBrokerSA: "auth-broker-tee@prod-femled-couple-router.iam.gserviceaccount.com"}
	if err := validateRuntimeClaims(c, cfg, &verifyReport{}); err == nil {
		t.Fatal("expected missing broker SA to fail")
	}
}

func TestValidateRuntimeClaims_HappyPath(t *testing.T) {
	c := &csClaims{
		Submods:               map[string]any{"container": map[string]any{"cmd_override": []any{}, "env_override": map[string]any{"GCP_PROJECT_ID": "x"}}},
		GoogleServiceAccounts: []string{"auth-broker-tee@prod-femled-couple-router.iam.gserviceaccount.com"},
	}
	cfg := &config{allowedEnvOverrideKeys: defaultAllowedEnvOverrideKeys, expectedBrokerSA: "auth-broker-tee@prod-femled-couple-router.iam.gserviceaccount.com"}
	if err := validateRuntimeClaims(c, cfg, &verifyReport{}); err != nil {
		t.Fatalf("happy-path runtime claims should pass: %v", err)
	}
}

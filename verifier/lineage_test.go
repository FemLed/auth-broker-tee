package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func TestValidateGovernanceLineageRejectsMalformedGenesis(t *testing.T) {
	_, priv, pubPEM := testEd25519Key(t)
	genesis := testGovernanceEnvelope(t, priv, map[string]any{
		"schema":                      "femled.tee.governance.successor.v1",
		"epoch":                       float64(1),
		"governancePublicKeyPem":      pubPEM,
		"governanceKeyId":             testKeyID(t, pubPEM),
		"imageDigest":                 "sha256:" + strings.Repeat("a", 64),
		"model":                       "gemini-3.1-pro-preview",
		"firstPrinciplesPromptDigest": "sha256:" + strings.Repeat("b", 64),
		"responseSchemaDigest":        "sha256:" + strings.Repeat("c", 64),
		"modelPolicyDigest":           "sha256:" + strings.Repeat("d", 64),
	})
	_, _, _, _, _, err := validateGovernanceLineage([]any{genesis})
	if err == nil || !strings.Contains(err.Error(), "genesis schema mismatch") {
		t.Fatalf("expected genesis schema mismatch, got %v", err)
	}

	genesisPayload := genesis["payload"].(map[string]any)
	genesisPayload["schema"] = "femled.tee.governance.genesis.v1"
	genesisPayload["epoch"] = float64(2)
	genesis = testGovernanceEnvelope(t, priv, genesisPayload)
	_, _, _, _, _, err = validateGovernanceLineage([]any{genesis})
	if err == nil || !strings.Contains(err.Error(), "genesis epoch") {
		t.Fatalf("expected genesis epoch failure, got %v", err)
	}
}

func TestValidateLineageContinuityPolicy(t *testing.T) {
	genesis := map[string]any{"payloadDigest": "sha256:" + strings.Repeat("a", 64)}
	successor := map[string]any{"payloadDigest": "sha256:" + strings.Repeat("b", 64)}
	lineage := []any{genesis, successor}
	lineageDigest, err := canonicalDigest(lineage)
	if err != nil {
		t.Fatal(err)
	}
	predecessorDigest, err := canonicalDigest(lineage[:1])
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLineageContinuityPolicy(lineage, lineageDigest, 2, &config{
		pinnedGovernanceLineageDigest:  lineageDigest,
		pinnedPredecessorLineageDigest: predecessorDigest,
		requireSuccessorLineage:        true,
		minGovernanceEpoch:             2,
	}); err != nil {
		t.Fatalf("expected continuity policy to pass: %v", err)
	}
	if err := validateLineageContinuityPolicy([]any{genesis}, "sha256:x", 1, &config{requireSuccessorLineage: true}); err == nil {
		t.Fatal("expected fresh genesis to fail when successor lineage is required")
	}
	if err := validateLineageContinuityPolicy(lineage, lineageDigest, 2, &config{pinnedGovernanceLineageDigest: "sha256:wrong"}); err == nil {
		t.Fatal("expected exact lineage pin mismatch to fail")
	}
	if err := validateLineageContinuityPolicy(lineage, lineageDigest, 1, &config{minGovernanceEpoch: 2}); err == nil {
		t.Fatal("expected min epoch failure")
	}
	if err := validateLineageContinuityPolicy(lineage, lineageDigest, 2, &config{pinnedPredecessorLineageDigest: "sha256:wrong"}); err == nil {
		t.Fatal("expected predecessor lineage pin mismatch")
	}
}

func testEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func testGovernanceEnvelope(t *testing.T, priv ed25519.PrivateKey, payload map[string]any) map[string]any {
	t.Helper()
	payloadDigest, err := canonicalDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"schema":        "femled.tee.governance.envelope.v1",
		"payload":       payload,
		"payloadDigest": payloadDigest,
		"signingKeyId":  testKeyIDFromPrivate(t, priv),
		"signature": map[string]any{
			"alg": "Ed25519",
			"sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, canonical)),
		},
	}
}

func testKeyIDFromPrivate(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return keyIDForPublicKeyDER(t, der)
}

func testKeyID(t *testing.T, publicKeyPEM string) string {
	t.Helper()
	pub, err := parseGovernancePublicKey(publicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return keyIDForPublicKeyDER(t, der)
}

func keyIDForPublicKeyDER(t *testing.T, der []byte) string {
	t.Helper()
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		t.Fatal("not ed25519")
	}
	return keyIDForGovernancePublicKey(pub)
}

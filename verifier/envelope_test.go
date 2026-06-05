package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// Regression test for the KMS-backed governance signer bug where the
// signer omitted its signatureAlgorithm field and signGovernancePayload
// labelled DER-encoded ECDSA P-256 signatures as "Ed25519". The running
// broker still verified them because Node's crypto.verify(null, ...)
// auto-routes by key type, but this verifier strictly checked the alg
// label and rejected the certs. After the fix, the verifier routes
// verification by the actual public-key type (matching the broker) and
// accepts either the correct "ECDSA_P256_SHA256" label OR the legacy
// mis-labelled "Ed25519" form on an EC key for at least one lineage
// cycle after the rollout.

func TestVerifyGovernanceEnvelopeAcceptsEd25519(t *testing.T) {
	_, priv, pubPEM := testEd25519Key(t)
	env := testGovernanceEnvelope(t, priv, map[string]any{
		"schema": "test.payload",
		"hello":  "world",
	})
	if err := verifyGovernanceEnvelopeMap(env, pubPEM); err != nil {
		t.Fatalf("expected Ed25519 envelope to verify: %v", err)
	}
}

func TestVerifyGovernanceEnvelopeAcceptsEcdsaP256(t *testing.T) {
	priv, pubPEM := testEcdsaP256Key(t)
	env := signEcdsaP256GovernanceEnvelope(t, priv, "ECDSA_P256_SHA256", map[string]any{
		"schema": "test.payload",
		"hello":  "world",
	})
	if err := verifyGovernanceEnvelopeMap(env, pubPEM); err != nil {
		t.Fatalf("expected ECDSA P-256 envelope to verify with explicit alg label: %v", err)
	}
}

func TestVerifyGovernanceEnvelopeAcceptsEcdsaP256LabelledAsEd25519(t *testing.T) {
	// Legacy compat: covers the genesis cert that the running TEE signed
	// before this fix landed. The label is wrong but the key is EC and
	// the signature is valid ECDSA-DER; the broker (and now this verifier)
	// route verification by key type, not by label.
	priv, pubPEM := testEcdsaP256Key(t)
	env := signEcdsaP256GovernanceEnvelope(t, priv, "Ed25519", map[string]any{
		"schema": "test.payload",
		"hello":  "world",
	})
	if err := verifyGovernanceEnvelopeMap(env, pubPEM); err != nil {
		t.Fatalf("expected ECDSA-P-256 cert mis-labelled as Ed25519 to verify under permissive auto-routing: %v", err)
	}
}

func TestVerifyGovernanceEnvelopeRejectsUnknownAlg(t *testing.T) {
	priv, pubPEM := testEcdsaP256Key(t)
	env := signEcdsaP256GovernanceEnvelope(t, priv, "RSA-PSS", map[string]any{
		"schema": "test.payload",
		"hello":  "world",
	})
	err := verifyGovernanceEnvelopeMap(env, pubPEM)
	if err == nil || !strings.Contains(err.Error(), "alg must be") {
		t.Fatalf("expected unknown alg to be rejected, got %v", err)
	}
}

func TestVerifyGovernanceEnvelopeRejectsForgedSignature(t *testing.T) {
	priv, pubPEM := testEcdsaP256Key(t)
	env := signEcdsaP256GovernanceEnvelope(t, priv, "ECDSA_P256_SHA256", map[string]any{
		"schema": "test.payload",
		"hello":  "world",
	})
	// Flip the first byte of the signature; ECDSA verify must reject.
	sigObj := env["signature"].(map[string]any)
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigObj["sig"].(string))
	if err != nil {
		t.Fatal(err)
	}
	sigBytes[0] ^= 0x01
	sigObj["sig"] = base64.RawURLEncoding.EncodeToString(sigBytes)
	if err := verifyGovernanceEnvelopeMap(env, pubPEM); err == nil {
		t.Fatal("expected forged ECDSA signature to be rejected")
	}
}

func testEcdsaP256Key(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return priv, pem
}

func signEcdsaP256GovernanceEnvelope(t *testing.T, priv *ecdsa.PrivateKey, label string, payload map[string]any) map[string]any {
	t.Helper()
	payloadDigest, err := canonicalDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256(der)
	return map[string]any{
		"schema":        "femled.tee.governance.envelope.v1",
		"payload":       payload,
		"payloadDigest": payloadDigest,
		"signingKeyId":  "sha256:" + asHex(keyDigest[:]),
		"signature": map[string]any{
			"alg": label,
			"sig": base64.RawURLEncoding.EncodeToString(sig),
		},
	}
}

func asHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

// Reference Ed25519 verification path stays untouched; this verifier
// already had Ed25519 coverage indirectly via lineage tests, but the
// dedicated TestVerifyGovernanceEnvelopeAcceptsEd25519 above pins it
// alongside the new ECDSA paths to keep both wired.
var _ = ed25519.PublicKey{}

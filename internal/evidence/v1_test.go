package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

func TestSecurityEvidenceV1_SigningAndVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyID := signing.KeyID(pub)
	trustedKeys := map[string]string{
		keyID: base64.StdEncoding.EncodeToString(pub),
	}

	scanRes := skil.ScanResult{
		Status:  skil.StatusPass,
		Verdict: skil.VerdictClear,
		Completeness: skil.InspectionSummary{
			Completeness: 1.0,
		},
	}

	ev := NewSecurityEvidenceV1("sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", "compiled-skill", "test-skill", "1.0.0", scanRes, nil)

	if ev.SchemaVersion != SchemaVersionV1 {
		t.Errorf("Expected SchemaVersion %s, got %s", SchemaVersionV1, ev.SchemaVersion)
	}

	if ev.EvidenceDigest == "" {
		t.Errorf("Expected non-empty EvidenceDigest")
	}

	env, err := ev.SignDSSE(priv, keyID)
	if err != nil {
		t.Fatalf("SignDSSE failed: %v", err)
	}

	verifiedEv, err := VerifySignedEvidence(env, trustedKeys)
	if err != nil {
		t.Fatalf("VerifySignedEvidence failed: %v", err)
	}

	if verifiedEv.Subject.Digest != ev.Subject.Digest {
		t.Errorf("Subject digest mismatch: %s != %s", verifiedEv.Subject.Digest, ev.Subject.Digest)
	}
}

func TestSecurityEvidenceV1_DigestTamperDetection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyID := signing.KeyID(pub)

	scanRes := skil.ScanResult{
		Status: skil.StatusPass,
	}

	ev := NewSecurityEvidenceV1("sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", "package", "tamper-skill", "1.0.0", scanRes, nil)
	env, err := ev.SignDSSE(priv, keyID)
	if err != nil {
		t.Fatalf("SignDSSE failed: %v", err)
	}

	// Tamper with key in trusted map
	untrustedKeys := map[string]string{
		keyID: base64.StdEncoding.EncodeToString(pub[:31]), // Corrupt key
	}

	_, err = VerifySignedEvidence(env, untrustedKeys)
	if err == nil {
		t.Errorf("Expected verification error for untrusted key, got success")
	}
}

func TestSecurityEvidenceV1DoesNotInventCompletenessTrustOrVerification(t *testing.T) {
	ev := NewSecurityEvidenceV1("sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", "skill", "x", "1", skil.ScanResult{Status: skil.StatusPass, Verdict: skil.VerdictClear}, nil)
	if ev.Complete || ev.Assurance.ClosureState != "UNKNOWN" || ev.Verification.DeclaredVsObservedMatch || ev.Risk.TrustLevel != "UNVERIFIED" {
		t.Fatalf("missing evidence increased assurance: %#v", ev)
	}
}

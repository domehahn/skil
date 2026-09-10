package interop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/domehahn/skil/internal/signing"
)

func TestSKGateInterop_CleanEvidence(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyID := signing.KeyID(pub)
	evaluator := &SKGateAdmissionEvaluator{
		Policy: DefaultAdmissionPolicy(),
		TrustedKeys: map[string]string{
			keyID: base64.StdEncoding.EncodeToString(pub),
		},
	}

	digest := "sha256:a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890"
	signedEv, err := GenerateSignedTestEvidence(priv, digest, "CLEAR", 95.0)
	if err != nil {
		t.Fatalf("GenerateSignedTestEvidence failed: %v", err)
	}

	result := evaluator.EvaluateAdmission(digest, signedEv)
	if result.Decision != DecisionAllow {
		t.Errorf("Expected DecisionAllow, got %s (reason: %s)", result.Decision, result.Reason)
	}
}

func TestSKGateInterop_SubjectDigestMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyID := signing.KeyID(pub)
	evaluator := &SKGateAdmissionEvaluator{
		Policy: DefaultAdmissionPolicy(),
		TrustedKeys: map[string]string{
			keyID: base64.StdEncoding.EncodeToString(pub),
		},
	}

	evidenceDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	requestedDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	signedEv, err := GenerateSignedTestEvidence(priv, evidenceDigest, "CLEAR", 95.0)
	if err != nil {
		t.Fatalf("GenerateSignedTestEvidence failed: %v", err)
	}

	result := evaluator.EvaluateAdmission(requestedDigest, signedEv)
	if result.Decision != DecisionReassess {
		t.Errorf("Expected DecisionReassess for digest mismatch, got %s (reason: %s)", result.Decision, result.Reason)
	}
}

func TestSKGateInterop_BlockVerdict(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyID := signing.KeyID(pub)
	evaluator := &SKGateAdmissionEvaluator{
		Policy: DefaultAdmissionPolicy(),
		TrustedKeys: map[string]string{
			keyID: base64.StdEncoding.EncodeToString(pub),
		},
	}

	digest := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	signedEv, err := GenerateSignedTestEvidence(priv, digest, "BLOCK", 20.0)
	if err != nil {
		t.Fatalf("GenerateSignedTestEvidence failed: %v", err)
	}

	result := evaluator.EvaluateAdmission(digest, signedEv)
	if result.Decision != DecisionDeny {
		t.Errorf("Expected DecisionDeny for BLOCK verdict, got %s (reason: %s)", result.Decision, result.Reason)
	}
}

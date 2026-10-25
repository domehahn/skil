package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/signing"
)

func TestVerifyReceipt_CleanReceipt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyID := signing.KeyID(pub)
	trustedKeys := map[string]string{
		keyID: base64.StdEncoding.EncodeToString(pub),
	}

	digest := "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
	policy := "sha256:aabbccddeeff11223344556677889900aabbccddeeff1122334455667788"

	receipt := &SKRunReceiptV1{
		ReceiptVersion: ReceiptVersionV1,
		ExecutionID:    "exec-12345",
		RuntimeBackend: "containerd-gVisor",
		SubjectDigest:  digest,
		PolicyDigest:   policy,
		Status:         "SUCCESS",
		Isolation: IsolationSummary{
			NativeIsolationActive: true,
			SandboxMode:           "container",
			NetworkSandboxed:      true,
		},
		ResourceUsage: ResourceUsageSummary{
			DurationMS:     450,
			MaxMemoryBytes: 1024 * 1024 * 64,
			CPUTimeMS:      210,
		},
		IssuedAt: time.Now().UTC(),
	}

	if err := receipt.SignReceipt(priv, keyID); err != nil {
		t.Fatalf("SignReceipt failed: %v", err)
	}

	res := VerifyReceipt(receipt, VerificationOptions{
		ExpectedSubjectDigest:  digest,
		ExpectedPolicyDigest:   policy,
		RequireNativeIsolation: true,
		TrustedKeys:            trustedKeys,
	})

	if !res.Valid {
		t.Errorf("Expected valid receipt verification, got invalid (reason: %s)", res.Reason)
	}
}

func TestVerifyReceipt_SubjectDigestMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyID := signing.KeyID(pub)
	trustedKeys := map[string]string{
		keyID: base64.StdEncoding.EncodeToString(pub),
	}

	receipt := &SKRunReceiptV1{
		ReceiptVersion: ReceiptVersionV1,
		ExecutionID:    "exec-67890",
		RuntimeBackend: "sandbox",
		SubjectDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Status:         "SUCCESS",
		IssuedAt:       time.Now().UTC(),
	}

	if err := receipt.SignReceipt(priv, keyID); err != nil {
		t.Fatalf("SignReceipt failed: %v", err)
	}

	res := VerifyReceipt(receipt, VerificationOptions{
		ExpectedSubjectDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		TrustedKeys:           trustedKeys,
	})

	if res.Valid {
		t.Errorf("Expected invalid receipt verification for digest mismatch, got valid")
	}
}

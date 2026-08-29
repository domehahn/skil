package signing

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestBindSessionDigestAddsEvidenceToAttestation(t *testing.T) {
	attestation := &skil.Attestation{
		Subject: skil.Subject{Name: "test-skill", SHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
	}

	opts := SessionContextOptions{
		SystemPrompt:  "You are a helpful coding assistant.",
		Temperature:   0.2,
		Seed:          42,
		SessionMemory: "User asked to refactor auth system.",
	}

	digest := BindSessionDigest(attestation, opts)
	if digest == "" {
		t.Fatalf("expected non-empty session digest")
	}

	if len(attestation.Evidence) == 0 {
		t.Fatalf("expected evidence to be appended to attestation")
	}

	lastEv := attestation.Evidence[len(attestation.Evidence)-1]
	if lastEv.PayloadDigest != digest {
		t.Fatalf("expected evidence payload digest to match session digest")
	}
}

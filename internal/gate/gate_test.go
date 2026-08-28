package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/pkg/skil"
)

func TestCheckGateValidAdmissionPasses(t *testing.T) {
	tempDir := t.TempDir()

	// Create test artifact
	artPath := filepath.Join(tempDir, "SKILL.md")
	if err := os.WriteFile(artPath, []byte("# Test Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}

	art, err := artifact.Load(tempDir, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	attDir := t.TempDir()
	att := skil.Attestation{
		Subject: skil.Subject{
			Name:   "my-test-skill",
			SHA256: art.SubjectDigest(),
		},
		Result: skil.AttestResult{
			Status:  skil.StatusPass,
			Verdict: skil.VerdictClear,
		},
	}
	attBytes, _ := json.Marshal(att)
	attPath := filepath.Join(attDir, "attestation.json")
	if err := os.WriteFile(attPath, attBytes, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := CheckGate(GateOptions{
		ArtifactPath:    tempDir,
		AttestationPath: attPath,
	})
	if err != nil {
		t.Fatalf("CheckGate failed: %v", err)
	}

	if !result.Allowed {
		t.Fatalf("expected gate admission to pass, got denial: %s", result.Reason)
	}
}

func TestCheckGateSubjectDigestMismatchDenied(t *testing.T) {
	tempDir := t.TempDir()
	artPath := filepath.Join(tempDir, "SKILL.md")
	if err := os.WriteFile(artPath, []byte("# Test Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Attestation with wrong digest
	att := skil.Attestation{
		Subject: skil.Subject{
			Name:   "my-test-skill",
			SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	attBytes, _ := json.Marshal(att)
	attPath := filepath.Join(tempDir, "attestation.json")
	if err := os.WriteFile(attPath, attBytes, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := CheckGate(GateOptions{
		ArtifactPath:    tempDir,
		AttestationPath: attPath,
	})
	if err != nil {
		t.Fatalf("CheckGate failed: %v", err)
	}

	if result.Allowed {
		t.Fatalf("expected gate admission to be denied due to digest mismatch")
	}
}

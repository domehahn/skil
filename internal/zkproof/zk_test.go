package zkproof

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestZKProofGeneratesAndVerifiesCommitment(t *testing.T) {
	tempDir := t.TempDir()

	skillFile := filepath.Join(tempDir, "SKILL.md")
	if err := os.WriteFile(skillFile, []byte("# Safe Proprietary Skill\n\nThis is proprietary code.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	proof, err := GenerateZKProof(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("GenerateZKProof failed: %v", err)
	}

	if !proof.IsProved {
		t.Fatalf("expected ZK proof to be proved for safe skill")
	}

	if !VerifyZKProof(proof) {
		t.Fatalf("expected ZK proof verification to succeed")
	}
}

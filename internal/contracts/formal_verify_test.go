package contracts

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyFormalContractProvesCleanSkill(t *testing.T) {
	tempDir := t.TempDir()

	skillFile := filepath.Join(tempDir, "SKILL.md")
	if err := os.WriteFile(skillFile, []byte("# Clean Skill\n\nThis is a safe skill.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	proof, err := VerifyFormalContract(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("VerifyFormalContract failed: %v", err)
	}

	if !proof.IsProved {
		t.Fatalf("expected formal proof to succeed for clean skill")
	}
}

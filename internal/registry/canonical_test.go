package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestCanonicalFingerprintNormalization(t *testing.T) {
	files1 := []skil.File{
		{Path: "SKILL.md", Data: []byte("name: k8s-deployer\r\ndescription: test\r\n")},
		{Path: "skil.yaml", Data: []byte("domain: [kubernetes]\r\n")},
	}
	files2 := []skil.File{
		{Path: "skil.yaml", Data: []byte("domain: [kubernetes]\n")},
		{Path: "SKILL.md", Data: []byte("name: k8s-deployer\ndescription: test\n")},
	}

	fp1, err := CanonicalFingerprint("", files1)
	if err != nil {
		t.Fatalf("fp1 error: %v", err)
	}

	fp2, err := CanonicalFingerprint("", files2)
	if err != nil {
		t.Fatalf("fp2 error: %v", err)
	}

	if fp1.Value != fp2.Value {
		t.Fatalf("expected identical SHA-256 fingerprints despite line endings and file ordering, got %s vs %s", fp1.Value, fp2.Value)
	}
}

func TestCanonicalFingerprintWorkspaceIgnoresTransient(t *testing.T) {
	tempDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tempDir, "SKILL.md"), []byte("# My Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, ".DS_Store"), []byte("garbage"), 0644); err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(tempDir, ".git")
	_ = os.MkdirAll(gitDir, 0755)
	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main"), 0644)

	fp, err := CanonicalFingerprint(tempDir, nil)
	if err != nil {
		t.Fatalf("CanonicalFingerprint failed: %v", err)
	}

	if fp.FileCount != 1 {
		t.Fatalf("expected 1 file to be fingerprinted, got %d", fp.FileCount)
	}
}

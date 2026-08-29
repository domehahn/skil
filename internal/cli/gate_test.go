package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/pkg/skil"
)

func TestGateCheckCommandSuccess(t *testing.T) {
	tempDir := t.TempDir()
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

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"gate", "check",
		"--artifact", tempDir,
		"--attestation", attPath,
		"--format", "json",
	})

	if code != ExitOK {
		t.Fatalf("expected ExitOK (0), got %d. stderr: %s", code, stderr.String())
	}
}

func TestGateCheckCommandDigestMismatchFails(t *testing.T) {
	tempDir := t.TempDir()
	artPath := filepath.Join(tempDir, "SKILL.md")
	if err := os.WriteFile(artPath, []byte("# Test Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}

	attDir := t.TempDir()
	att := skil.Attestation{
		Subject: skil.Subject{
			Name:   "my-test-skill",
			SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	attBytes, _ := json.Marshal(att)
	attPath := filepath.Join(attDir, "attestation.json")
	if err := os.WriteFile(attPath, attBytes, 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"gate", "check",
		"--artifact", tempDir,
		"--attestation", attPath,
	})

	if code == ExitOK {
		t.Fatalf("expected failure for digest mismatch, got ExitOK")
	}
}

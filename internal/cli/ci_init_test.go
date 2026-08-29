package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCIInitCLICommand(t *testing.T) {
	tempDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{"ci", "init", "--workspace", tempDir, "--platform", "github"})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for ci init github, got %d. stderr: %s", code, stderr.String())
	}

	ghPath := filepath.Join(tempDir, ".github", "workflows", "skil-security.yml")
	if _, err := os.Stat(ghPath); os.IsNotExist(err) {
		t.Fatalf("expected github workflow file to exist at %s", ghPath)
	}

	code = app.Run(context.Background(), []string{"ci", "init", "--workspace", tempDir, "--platform", "gitlab"})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for ci init gitlab, got %d. stderr: %s", code, stderr.String())
	}

	glPath := filepath.Join(tempDir, ".gitlab-ci.yml")
	if _, err := os.Stat(glPath); os.IsNotExist(err) {
		t.Fatalf("expected gitlab ci file to exist at %s", glPath)
	}
}

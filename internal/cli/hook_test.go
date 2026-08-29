package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHookInstallAndUninstallCLI(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{"hook", "install", "--workspace", tempDir})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for hook install, got %d. stderr: %s", code, stderr.String())
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		t.Fatalf("expected pre-commit hook file to exist after install")
	}

	code = app.Run(context.Background(), []string{"hook", "uninstall", "--workspace", tempDir})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for hook uninstall, got %d. stderr: %s", code, stderr.String())
	}

	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatalf("expected pre-commit hook file to be uninstalled")
	}
}

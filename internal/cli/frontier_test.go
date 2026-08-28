package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFrontierCLICommands(t *testing.T) {
	tempDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	// 1. mesh verify
	code := app.Run(context.Background(), []string{"mesh", "verify", "--workspace", tempDir})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for mesh verify, got %d. stderr: %s", code, stderr.String())
	}

	// 2. stego scan
	stegoFile := filepath.Join(tempDir, "clean.md")
	if err := os.WriteFile(stegoFile, []byte("# Clean File\nNo stego here.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	code = app.Run(context.Background(), []string{"stego", "scan", stegoFile})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for stego scan clean file, got %d. stderr: %s", code, stderr.String())
	}

	// 3. sandbox run
	code = app.Run(context.Background(), []string{"sandbox", "run", "--workspace", tempDir, "echo", "sandbox_test"})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for sandbox run echo, got %d. stderr: %s", code, stderr.String())
	}
}

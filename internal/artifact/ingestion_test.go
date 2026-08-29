package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureIngestorRejectsSymlinkEscapes(t *testing.T) {
	tempDir := t.TempDir()
	outsideDir := t.TempDir()

	secretFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("SENSITIVE DATA"), 0o600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	symlinkFile := filepath.Join(tempDir, "symlink_escape.txt")
	if err := os.Symlink(secretFile, symlinkFile); err != nil {
		t.Skipf("symlinks not supported on this platform: %v", err)
	}

	ingestor, err := NewSecureIngestor(tempDir)
	if err != nil {
		t.Fatalf("failed to create ingestor: %v", err)
	}

	_, _, err = ingestor.ReadFileSafely("symlink_escape.txt", 1024)
	if err == nil {
		t.Fatalf("expected ReadFileSafely to reject symlink escape to %s", secretFile)
	}
}

func TestSecureIngestorRejectsPathEscapes(t *testing.T) {
	tempDir := t.TempDir()
	ingestor, err := NewSecureIngestor(tempDir)
	if err != nil {
		t.Fatalf("failed to create ingestor: %v", err)
	}

	badPaths := []string{
		"../foo",
		"../../etc/passwd",
		"/etc/passwd",
		"a/../../b",
	}

	for _, path := range badPaths {
		_, _, err := ingestor.ReadFileSafely(path, 1024)
		if err == nil {
			t.Fatalf("expected path escape rejection for %q", path)
		}
	}
}

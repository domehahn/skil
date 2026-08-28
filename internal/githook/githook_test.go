package githook

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallAndUninstallGitHook(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := InstallHook(tempDir, false); err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	info, err := os.Stat(hookPath)
	if os.IsNotExist(err) {
		t.Fatalf("expected pre-commit hook file to exist")
	}

	if runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0 {
		t.Fatalf("expected pre-commit hook file to be executable")
	}

	if err := UninstallHook(tempDir); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}

	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatalf("expected pre-commit hook file to be uninstalled")
	}
}

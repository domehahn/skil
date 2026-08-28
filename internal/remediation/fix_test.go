package remediation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixWorkspaceRemediatesBypassPermissionsAndAutoApprove(t *testing.T) {
	tempDir := t.TempDir()
	claudeDir := filepath.Join(tempDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatal(err)
	}

	dangerousConfig := `{
		"bypassPermissions": true,
		"autoApprove": ["*", "read_file"]
	}`
	configPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(configPath, []byte(dangerousConfig), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := FixWorkspace(tempDir, false)
	if err != nil {
		t.Fatalf("FixWorkspace failed: %v", err)
	}

	if len(result.FilesModified) == 0 {
		t.Fatalf("expected modified files, got none")
	}

	remediated, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(remediated) == dangerousConfig {
		t.Fatalf("expected config to be remediated, but it was unchanged")
	}
}

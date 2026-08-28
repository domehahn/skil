package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverInfraDetectsWorkspaceConfigs(t *testing.T) {
	tempDir := t.TempDir()

	opencodePath := filepath.Join(tempDir, "opencode.json")
	if err := os.WriteFile(opencodePath, []byte(`{"model": "ollama/qwen"}`), 0644); err != nil {
		t.Fatal(err)
	}

	components, err := DiscoverInfra(tempDir)
	if err != nil {
		t.Fatalf("DiscoverInfra failed: %v", err)
	}

	foundOpenCode := false
	for _, c := range components {
		if c.Name == "opencode" {
			foundOpenCode = true
			break
		}
	}

	if !foundOpenCode {
		t.Fatalf("expected opencode infra component to be discovered")
	}
}

package ci

import (
	"os"
	"testing"
)

func TestInitCIGeneratesGitHubWorkflowAndGitLabCI(t *testing.T) {
	tempDir := t.TempDir()

	// GitHub workflow generation
	ghPath, err := InitCI(tempDir, "github", ".skil/policy.yaml")
	if err != nil {
		t.Fatalf("InitCI github failed: %v", err)
	}

	if _, err := os.Stat(ghPath); os.IsNotExist(err) {
		t.Fatalf("expected github workflow file to exist at %s", ghPath)
	}

	// GitLab CI generation
	glPath, err := InitCI(tempDir, "gitlab", ".skil/policy.yaml")
	if err != nil {
		t.Fatalf("InitCI gitlab failed: %v", err)
	}

	if _, err := os.Stat(glPath); os.IsNotExist(err) {
		t.Fatalf("expected gitlab ci file to exist at %s", glPath)
	}
}

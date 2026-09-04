package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIRegistryWorkflow(t *testing.T) {
	tempDir := t.TempDir()
	catalogPath := filepath.Join(tempDir, "catalog.json")

	// Create test skills
	skill1Dir := filepath.Join(tempDir, "kubernetes-deployer")
	if err := os.MkdirAll(skill1Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill1Dir, "SKILL.md"), []byte("# Kubernetes Deployer\nDeploy applications and Helm charts into Kubernetes.\nActions: deploy, rollback, health-check.\nTools: kubectl, helm.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	skill2Dir := filepath.Join(tempDir, "exact-copy")
	if err := os.MkdirAll(skill2Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill2Dir, "SKILL.md"), []byte("# Kubernetes Deployer\nDeploy applications and Helm charts into Kubernetes.\nActions: deploy, rollback, health-check.\nTools: kubectl, helm.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)
	ctx := context.Background()

	// 1. Index skill1
	code := app.Run(ctx, []string{"registry", "index", skill1Dir, "--catalog", catalogPath})
	if code != ExitOK {
		t.Fatalf("expected ExitOK for registry index, got %d. Stderr: %s", code, stderr.String())
	}

	// 2. List catalog
	stdout.Reset()
	code = app.Run(ctx, []string{"registry", "list", "--catalog", catalogPath})
	if code != ExitOK {
		t.Fatalf("expected ExitOK for registry list, got %d", code)
	}
	if !strings.Contains(stdout.String(), "kubernetes-deployer") {
		t.Fatalf("expected kubernetes-deployer in list output, got:\n%s", stdout.String())
	}

	// 3. Search catalog
	stdout.Reset()
	code = app.Run(ctx, []string{"registry", "search", "deploy applications to kubernetes", "--catalog", catalogPath})
	if code != ExitOK {
		t.Fatalf("expected ExitOK for registry search, got %d", code)
	}
	if !strings.Contains(stdout.String(), "kubernetes-deployer") {
		t.Fatalf("expected kubernetes-deployer in search output, got:\n%s", stdout.String())
	}

	// 4. Check exact duplicate (skill2Dir vs catalog)
	stdout.Reset()
	code = app.Run(ctx, []string{"registry", "check", skill2Dir, "--catalog", catalogPath})
	if code != ExitAdmissionReject {
		t.Fatalf("expected ExitAdmissionReject (2) for exact duplicate check, got %d. Output:\n%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "EXACT_DUPLICATE") {
		t.Fatalf("expected EXACT_DUPLICATE in check output, got:\n%s", stdout.String())
	}

	// 5. Compare candidate with existing
	stdout.Reset()
	code = app.Run(ctx, []string{"registry", "compare", skill2Dir, "kubernetes-deployer", "--catalog", catalogPath})
	if code != ExitOK {
		t.Fatalf("expected ExitOK for registry compare, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Similarity Scores") {
		t.Fatalf("expected Similarity Scores in compare output, got:\n%s", stdout.String())
	}
}

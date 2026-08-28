package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFlagshipCLICommands(t *testing.T) {
	tempDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	// 1. revoke add & check
	regPath := filepath.Join(tempDir, "revocations.json")
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	code := app.Run(context.Background(), []string{"revoke", "add", "--registry", regPath, digest})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for revoke add, got %d. stderr: %s", code, stderr.String())
	}

	code = app.Run(context.Background(), []string{"revoke", "check", "--registry", regPath, digest})
	if code != ExitGateFail {
		t.Fatalf("expected ExitGateFail (1) for revoked digest check, got %d", code)
	}

	// 2. zk prove
	skillFile := filepath.Join(tempDir, "SKILL.md")
	if err := os.WriteFile(skillFile, []byte("# Safe Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}
	code = app.Run(context.Background(), []string{"zk", "prove", tempDir})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for zk prove, got %d. stderr: %s", code, stderr.String())
	}

	// 3. policy adapt
	tracePath := filepath.Join(tempDir, "trace.json")
	if err := os.WriteFile(tracePath, []byte(`{"observed_capabilities": ["filesystem.read"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	outPolicyPath := filepath.Join(tempDir, "policy.yaml")
	code = app.Run(context.Background(), []string{"policy", "adapt", "--trace", tracePath, "--output", outPolicyPath})
	if code != ExitOK {
		t.Fatalf("expected ExitOK (0) for policy adapt, got %d. stderr: %s", code, stderr.String())
	}
}

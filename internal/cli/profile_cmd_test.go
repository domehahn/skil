package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileCheckCommandSuccess(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "mcp-surface.lock.json")
	if err := os.WriteFile(lockPath, []byte(`{"version": 1, "tools": {"test_tool": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(tempDir, "profile.secure.yaml")
	cfgYAML := fmt.Sprintf(`version: 1
profile: secure
environment: staging-secure
topology: single_process
gateway:
  audience_id: runtime://skil-staging
  trusted_issuers:
    skgate://security-authority:
      - sec-key-1
  trusted_public_keys:
    sec-key-1: O23b8Ld2vYy/c5pY0qD7U8m5BwH2e1k4L7n0P9q3Z1Y=
enforcement:
  mandatory_authorization: true
  require_proof_carrying: true
  audit_outcome_persistence: true
  audit_log_path: %s
  fail_closed: true
mcp:
  require_surface_lock: true
  surface_lock_path: %s
  validate_schemas: true
  strict_tools: true
replay:
  scope: process-local
assurance:
  oracle_enabled: true
  policy_id: test-policy
readiness:
  liveness_check_enabled: true
  readiness_check_enabled: true
  security_check_enabled: true
  require_fresh_assurance: true
`, filepath.Join(tempDir, "audit.jsonl"), lockPath)

	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"profile", "check",
		"--config", cfgPath,
		"--format", "json",
	})

	if code != ExitOK {
		t.Fatalf("expected ExitOK (0), got %d. stderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}

	var report map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON profile report: %v", err)
	}
	if report["valid"] != true || report["blocked"] != false {
		t.Fatalf("expected valid=true, blocked=false; got valid=%v, blocked=%v", report["valid"], report["blocked"])
	}
}

func TestProfileCheckCommandBlockedFails(t *testing.T) {
	tempDir := t.TempDir()
	badConfigPath := filepath.Join(tempDir, "invalid-prod.yaml")
	badYAML := `version: 1
profile: production
environment: dev-local
topology: distributed
replay:
  scope: host-durable
`
	if err := os.WriteFile(badConfigPath, []byte(badYAML), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"profile", "check",
		"--config", badConfigPath,
	})

	if code != ExitGateFail {
		t.Fatalf("expected ExitGateFail (%d), got %d. stdout: %s", ExitGateFail, code, stdout.String())
	}
}

func TestMCPInterceptRejectsStartupOnInvalidProfile(t *testing.T) {
	tempDir := t.TempDir()
	badConfigPath := filepath.Join(tempDir, "bad-profile.yaml")
	badYAML := `version: 1
profile: production
environment: production
topology: single_process
enforcement:
  mandatory_authorization: false
`
	if err := os.WriteFile(badConfigPath, []byte(badYAML), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"mcp", "intercept",
		"--profile", "production",
		"--profile-config", badConfigPath,
	})

	if code != ExitGateFail {
		t.Fatalf("expected ExitGateFail (%d), got %d. stderr: %s\nstdout: %s", ExitGateFail, code, stderr.String(), stdout.String())
	}
}

func TestProxyRejectsStartupOnInvalidProfile(t *testing.T) {
	tempDir := t.TempDir()
	badConfigPath := filepath.Join(tempDir, "bad-profile.yaml")
	badYAML := `version: 1
profile: production
environment: dev
topology: single_process
`
	if err := os.WriteFile(badConfigPath, []byte(badYAML), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"proxy", "serve",
		"--profile", "production",
		"--profile-config", badConfigPath,
	})

	if code != ExitGateFail {
		t.Fatalf("expected ExitGateFail (%d), got %d. stderr: %s\nstdout: %s", ExitGateFail, code, stderr.String(), stdout.String())
	}
}

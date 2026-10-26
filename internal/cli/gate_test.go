package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/pkg/skil"
)

func TestGateCheckCommandSuccess(t *testing.T) {
	tempDir := t.TempDir()
	artPath := filepath.Join(tempDir, "SKILL.md")
	if err := os.WriteFile(artPath, []byte("# Test Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}

	art, err := artifact.Load(tempDir, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	attDir := t.TempDir()
	att := skil.Attestation{
		Subject: skil.Subject{
			Name:   "my-test-skill",
			SHA256: art.SubjectDigest(),
		},
		Result: skil.AttestResult{
			Status:  skil.StatusPass,
			Verdict: skil.VerdictClear,
		},
	}
	attBytes, _ := json.Marshal(att)
	attPath := filepath.Join(attDir, "attestation.json")
	if err := os.WriteFile(attPath, attBytes, 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"gate", "check",
		"--artifact", tempDir,
		"--attestation", attPath,
		"--format", "json",
	})

	if code != ExitOK {
		t.Fatalf("expected ExitOK (0), got %d. stderr: %s", code, stderr.String())
	}
}

func TestGateCheckCommandDigestMismatchFails(t *testing.T) {
	tempDir := t.TempDir()
	artPath := filepath.Join(tempDir, "SKILL.md")
	if err := os.WriteFile(artPath, []byte("# Test Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}

	attDir := t.TempDir()
	att := skil.Attestation{
		Subject: skil.Subject{
			Name:   "my-test-skill",
			SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	attBytes, _ := json.Marshal(att)
	attPath := filepath.Join(attDir, "attestation.json")
	if err := os.WriteFile(attPath, attBytes, 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"gate", "check",
		"--artifact", tempDir,
		"--attestation", attPath,
	})

	if code == ExitOK {
		t.Fatalf("expected failure for digest mismatch, got ExitOK")
	}
}

func TestGateReleaseCommandSuccess(t *testing.T) {
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "policy.yaml")
	policyYAML := `version: 1
maximum_severity: MEDIUM
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(tempDir, "mcp-surface.lock.json")
	lockJSON := `{"version": 1, "tools": {"test_tool": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}`
	if err := os.WriteFile(lockPath, []byte(lockJSON), 0644); err != nil {
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
  policy_path: %s
  max_reconciliation_interval_seconds: 600
  freshness_threshold_seconds: 3600
readiness:
  liveness_check_enabled: true
  readiness_check_enabled: true
  security_check_enabled: true
  require_fresh_assurance: true
`, filepath.Join(tempDir, "audit.jsonl"), lockPath, policyPath)

	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"gate", "release",
		"--config", cfgPath,
		"--policy", policyPath,
		"--format", "json",
	})

	if code != ExitOK {
		t.Fatalf("expected ExitOK (0), got %d. stderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}

	var report map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON release gate report: %v", err)
	}
	if report["status"] != "READY" {
		t.Fatalf("expected READY status, got %v", report["status"])
	}
}

func TestGateReleaseCommandBlockedFails(t *testing.T) {
	tempDir := t.TempDir()
	badConfigPath := filepath.Join(tempDir, "bad-profile.yaml")
	// Production profile missing required audience and keys
	badYAML := `version: 1
profile: production
environment: production
topology: single_process
gateway:
  audience_id: ""
`
	if err := os.WriteFile(badConfigPath, []byte(badYAML), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"gate", "release",
		"--config", badConfigPath,
	})

	if code != ExitGateFail {
		t.Fatalf("expected ExitGateFail (%d), got %d. stdout: %s", ExitGateFail, code, stdout.String())
	}
}

package profile

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/mcpassure"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

func TestEvaluateReleaseGate_ReadyReport(t *testing.T) {
	now := time.Date(2026, 10, 26, 14, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := signing.KeyID(pub)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "mcp.lock.json")
	lockObj := mcpassure.SurfaceLock{Version: 1, Tools: map[string]string{"tool": "1234"}}
	rawLock, _ := json.Marshal(lockObj)
	_ = os.WriteFile(lockPath, rawLock, 0o600)

	nonceDir := filepath.Join(dir, "nonces")
	_ = os.MkdirAll(nonceDir, 0o700)

	attPath := filepath.Join(dir, "attestation.json")
	att := skil.Attestation{
		Version: 1,
		Subject: skil.Subject{Name: "test-skill", SHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Result:  skil.AttestResult{Status: skil.StatusPass},
	}
	_ = signing.SignAttestation(&att, priv, keyID)
	rawAtt, _ := json.Marshal(att)
	_ = os.WriteFile(attPath, rawAtt, 0o600)

	policyPath := filepath.Join(dir, "policy.yaml")
	_ = os.WriteFile(policyPath, []byte("version: 1\nmaximum_severity: HIGH\n"), 0o600)

	cfg := DefaultProductionConfig()
	cfg.Gateway.TrustedIssuers = map[string][]string{"skgate://authority": {keyID}}
	cfg.Gateway.TrustedPublicKeys = map[string]string{keyID: pubB64}
	cfg.MCP.SurfaceLockPath = lockPath
	cfg.Replay.DurableDir = nonceDir
	cfg.Enforcement.AuditLogPath = filepath.Join(dir, "audit.jsonl")
	cfg.Assurance.PolicyPath = policyPath

	report := EvaluateReleaseGate(ReleaseGateOptions{
		Config:          cfg,
		AttestationPath: attPath,
		PolicyPath:      policyPath,
		Now:             func() time.Time { return now },
	})

	if report.Status != GateStatusReady {
		t.Fatalf("expected release gate READY, got %s: %#v", report.Status, report)
	}
	if len(report.Checks) != 10 {
		t.Fatalf("expected 10 release checks, got %d", len(report.Checks))
	}
	for _, check := range report.Checks {
		if check.Status != CheckPass {
			t.Fatalf("check %s failed: %s (%s)", check.ID, check.Detail, check.Remediation)
		}
	}
}

func TestEvaluateReleaseGate_NotReadyOnMissingControls(t *testing.T) {
	cfg := DefaultProductionConfig()
	cfg.Gateway.AudienceID = "" // invalid!

	report := EvaluateReleaseGate(ReleaseGateOptions{
		Config: cfg,
	})

	if report.Status != GateStatusNotReady {
		t.Fatalf("expected NOT_READY, got %s", report.Status)
	}
}

func TestEvaluateReleaseGate_IncompleteWhenMissingProductionPrerequisites(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "mcp.lock.json")
	lockObj := mcpassure.SurfaceLock{Version: 1, Tools: map[string]string{"tool": "1234"}}
	rawLock, _ := json.Marshal(lockObj)
	_ = os.WriteFile(lockPath, rawLock, 0o600)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	cfg := DefaultProductionConfig()
	cfg.Gateway.TrustedIssuers = map[string][]string{"skgate://auth": {"key1"}}
	cfg.Gateway.TrustedPublicKeys = map[string]string{"key1": pubB64}
	cfg.MCP.SurfaceLockPath = lockPath
	cfg.Replay.DurableDir = dir
	cfg.Enforcement.AuditLogPath = filepath.Join(dir, "audit.jsonl")
	cfg.Assurance.PolicyPath = "" // missing policy path in production!

	report := EvaluateReleaseGate(ReleaseGateOptions{
		Config: cfg,
	})

	if report.Status != GateStatusIncomplete {
		t.Fatalf("expected INCOMPLETE when production attestation/policy path is missing, got %s: %#v", report.Status, report)
	}
}

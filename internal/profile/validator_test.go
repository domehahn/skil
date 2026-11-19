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
)

func TestValidateStartup_DevelopmentProfilePermissive(t *testing.T) {
	cfg := DefaultDevelopmentConfig()
	report := ValidateStartup(cfg, LiveEnvironmentState{})
	if report.Blocked || !report.Valid {
		t.Fatalf("development profile should not be blocked: %#v", report)
	}
}

func TestValidateStartup_ProductionValid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := signing.KeyID(pub)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "surface.lock.json")
	lockObj := mcpassure.SurfaceLock{
		Version: 1,
		Tools:   map[string]string{"query_tool": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
	}
	rawLock, _ := json.Marshal(lockObj)
	if err := os.WriteFile(lockPath, rawLock, 0o600); err != nil {
		t.Fatal(err)
	}

	nonceDir := filepath.Join(dir, "nonces")
	_ = os.MkdirAll(nonceDir, 0o700)

	cfg := DefaultProductionConfig()
	cfg.Gateway.TrustedIssuers = map[string][]string{"skgate://prod-auth": {keyID}}
	cfg.Gateway.TrustedPublicKeys = map[string]string{keyID: pubB64}
	cfg.MCP.SurfaceLockPath = lockPath
	cfg.Replay.DurableDir = nonceDir
	cfg.Enforcement.AuditLogPath = filepath.Join(dir, "audit.jsonl")

	report := ValidateStartup(cfg, LiveEnvironmentState{})
	if report.Blocked || !report.Valid {
		t.Fatalf("valid production startup should pass: blocked=%t count=%d findings=%#v", report.Blocked, report.BlockingCount, report.Findings)
	}
}

func TestValidateStartup_ProductionBlockingRejections(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "surface.lock.json")
	lockObj := mcpassure.SurfaceLock{Version: 1, Tools: map[string]string{"tool": "1111"}}
	rawLock, _ := json.Marshal(lockObj)
	_ = os.WriteFile(lockPath, rawLock, 0o600)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	baseCfg := func() DeploymentConfig {
		cfg := DefaultProductionConfig()
		cfg.Gateway.TrustedIssuers = map[string][]string{"skgate://auth": {"key1"}}
		cfg.Gateway.TrustedPublicKeys = map[string]string{"key1": pubB64}
		cfg.MCP.SurfaceLockPath = lockPath
		cfg.Replay.DurableDir = dir
		cfg.Enforcement.AuditLogPath = filepath.Join(dir, "audit.jsonl")
		return cfg
	}

	cases := []struct {
		name       string
		mutate     func(*DeploymentConfig)
		expectedID string
	}{
		{
			name: "missing_audience",
			mutate: func(c *DeploymentConfig) {
				c.Gateway.AudienceID = ""
			},
			expectedID: "SEC-GW-001",
		},
		{
			name: "missing_trusted_issuers",
			mutate: func(c *DeploymentConfig) {
				c.Gateway.TrustedIssuers = nil
			},
			expectedID: "SEC-KEY-001",
		},
		{
			name: "invalid_public_key_base64",
			mutate: func(c *DeploymentConfig) {
				c.Gateway.TrustedPublicKeys = map[string]string{"key1": "not-valid-base64!"}
			},
			expectedID: "SEC-KEY-003",
		},
		{
			name: "disabled_mandatory_auth",
			mutate: func(c *DeploymentConfig) {
				c.Enforcement.MandatoryAuthorization = false
			},
			expectedID: "SEC-AUTH-001",
		},
		{
			name: "missing_surface_lock",
			mutate: func(c *DeploymentConfig) {
				c.MCP.SurfaceLockPath = filepath.Join(dir, "non-existent.lock.json")
			},
			expectedID: "SEC-LOCK-003",
		},
		{
			name: "multi_process_with_process_local_replay",
			mutate: func(c *DeploymentConfig) {
				c.Topology = TopologyMultiProcessHost
				c.Replay.Scope = "process-local"
			},
			expectedID: "SEC-REPLAY-002",
		},
		{
			name: "distributed_topology_with_host_local_replay",
			mutate: func(c *DeploymentConfig) {
				c.Topology = TopologyDistributed
				c.Replay.Scope = "host-durable"
				c.Replay.DistributedStore = ""
			},
			expectedID: "SEC-REPLAY-004",
		},
		{
			name: "disabled_oracle",
			mutate: func(c *DeploymentConfig) {
				c.Assurance.OracleEnabled = false
			},
			expectedID: "SEC-ASSURE-001",
		},
		{
			name: "embedded_secret_token",
			mutate: func(c *DeploymentConfig) {
				c.Gateway.AudienceID = "sk-1234567890abcdefghijklmnop"
			},
			expectedID: "SEC-SECRET-001",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg()
			tc.mutate(&cfg)
			report := ValidateStartup(cfg, LiveEnvironmentState{})
			if !report.Blocked || report.Valid {
				t.Fatalf("expected case %s to be blocked, got: %#v", tc.name, report)
			}
			found := false
			for _, f := range report.Findings {
				if f.ControlID == tc.expectedID && f.Blocking {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected blocking finding %s, got: %#v", tc.expectedID, report.Findings)
			}
		})
	}
}

func TestValidateStartup_ZeroSecretsPrinted(t *testing.T) {
	cfg := DefaultProductionConfig()
	cfg.Gateway.AudienceID = "runtime://test"
	cfg.Enforcement.AuditLogPath = "bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	report := ValidateStartup(cfg, LiveEnvironmentState{})
	rawReport, _ := json.Marshal(report)
	if string(rawReport) == "" {
		t.Fatal("empty report")
	}
	if secretValuePattern.Match(rawReport) {
		t.Fatalf("report must never leak raw sensitive tokens: %s", string(rawReport))
	}
}

func (c *DeploymentConfig) nowOrSystem(nowFn func() time.Time) time.Time {
	if nowFn != nil {
		return nowFn().UTC()
	}
	return time.Now().UTC()
}

package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/continuous"
	"github.com/domehahn/skil/internal/mcpinterceptor"
	"github.com/domehahn/skil/internal/profile"
	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

// helper to create a valid base production configuration and test fixtures
func createTestProductionFixtures(t *testing.T) (profile.DeploymentConfig, string, string, string, *receipt.ExecutionGateway, string) {
	t.Helper()
	tempDir := t.TempDir()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	lockPath := filepath.Join(tempDir, "mcp-surface.lock.json")
	lockJSON := `{"version": 1, "tools": {"query_repo": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}`
	if err := os.WriteFile(lockPath, []byte(lockJSON), 0644); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(tempDir, "policy.yaml")
	policyYAML := `version: 1
maximum_severity: MEDIUM
require_runtime_enforcement: true
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(tempDir, "enforcement-audit.jsonl")
	durableNonceDir := filepath.Join(tempDir, "nonces")
	if err := os.MkdirAll(durableNonceDir, 0700); err != nil {
		t.Fatal(err)
	}

	att := skil.Attestation{
		Subject: skil.Subject{
			Name:   "test-skill",
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		Result: skil.AttestResult{
			Status:  skil.StatusPass,
			Verdict: skil.VerdictClear,
		},
	}
	if err := signing.SignAttestation(&att, privKey, "key-prod-2026"); err != nil {
		t.Fatal(err)
	}
	attBytes, _ := json.Marshal(att)
	attPath := filepath.Join(tempDir, "attestation.json")
	if err := os.WriteFile(attPath, attBytes, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := profile.DeploymentConfig{
		Version:     1,
		Profile:     profile.ProfileProduction,
		Environment: "production-eu-west-1",
		Topology:    profile.TopologyMultiProcessHost,
		Gateway: profile.GatewayDeploymentConfig{
			AudienceID: "runtime://skil-prod-gateway",
			TrustedIssuers: map[string][]string{
				"skgate://security-authority": {"key-prod-2026"},
			},
			TrustedPublicKeys: map[string]string{
				"key-prod-2026": pubKeyB64,
			},
			KeyRotation: profile.KeyRotationConfig{
				MaxKeyAgeHours:     720,
				RotationNoticeDays: 14,
				RequireActiveKey:   true,
			},
		},
		Enforcement: profile.EnforcementDeploymentConfig{
			MandatoryAuthorization:  true,
			RequireProofCarrying:    true,
			AuditOutcomePersistence: true,
			AuditLogPath:            auditPath,
			FailClosed:              true,
		},
		MCP: profile.MCPDeploymentConfig{
			RequireSurfaceLock: true,
			SurfaceLockPath:    lockPath,
			ValidateSchemas:    true,
			StrictTools:        true,
		},
		Replay: profile.ReplayDeploymentConfig{
			Scope:      receipt.ReplayScopeHostDurable,
			DurableDir: durableNonceDir,
		},
		Assurance: profile.AssuranceDeploymentConfig{
			OracleEnabled:                    true,
			PolicyID:                         "policy://prod-strict",
			PolicyPath:                       policyPath,
			MaxReconciliationIntervalSeconds: 300,
			FreshnessThresholdSeconds:        1800,
			RequireActiveReconciliation:      true,
		},
		Resources: profile.ResourceDeploymentConfig{
			MaxToolCalls:      16,
			MaxRuntimeSeconds: 10,
			MaxMemoryMB:       2048,
			MaxNetworkBytes:   10485760,
		},
		Readiness: profile.ReadinessDeploymentConfig{
			LivenessCheckEnabled:  true,
			ReadinessCheckEnabled: true,
			SecurityCheckEnabled:  true,
			RequireFreshAssurance: true,
		},
	}

	gw := receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
		RuntimeAudienceID: cfg.Gateway.AudienceID,
		TrustedIssuers:    cfg.Gateway.TrustedIssuers,
		TrustedPublicKeys: cfg.Gateway.TrustedPublicKeys,
	})

	return cfg, tempDir, lockPath, policyPath, gw, attPath
}

// Scenario 1: Production startup with valid configuration (PASS)
func TestDeploymentProfileE2E_01_ValidProductionStartup(t *testing.T) {
	cfg, _, _, _, _, attPath := createTestProductionFixtures(t)

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Valid || report.Blocked || report.BlockingCount > 0 {
		t.Fatalf("expected valid non-blocked report, got valid=%t, blocked=%t, findings: %+v",
			report.Valid, report.Blocked, report.Findings)
	}

	gateReport := profile.EvaluateReleaseGate(profile.ReleaseGateOptions{
		Config:          cfg,
		AttestationPath: attPath,
	})
	if gateReport.Status != profile.GateStatusReady {
		t.Fatalf("expected release gate READY, got %s (summary: %s)", gateReport.Status, gateReport.Summary)
	}
}

// Scenario 2: Production startup with missing gateway (BLOCKED)
func TestDeploymentProfileE2E_02_MissingGatewayBlocked(t *testing.T) {
	cfg, _, _, _, _, _ := createTestProductionFixtures(t)
	cfg.Gateway.AudienceID = ""
	cfg.Gateway.TrustedIssuers = nil

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Blocked {
		t.Fatalf("expected blocked startup on missing gateway, got valid=%t", report.Valid)
	}

	hasGWFinding := false
	for _, f := range report.Findings {
		if f.ControlID == "SEC-GW-001" && f.Blocking {
			hasGWFinding = true
			break
		}
	}
	if !hasGWFinding {
		t.Fatalf("expected SEC-GW-001 blocking finding, got: %+v", report.Findings)
	}
}

// Scenario 3: Missing or invalid trust roots (BLOCKED)
func TestDeploymentProfileE2E_03_InvalidTrustRootsBlocked(t *testing.T) {
	cfg, _, _, _, _, _ := createTestProductionFixtures(t)
	// Key ID referenced in TrustedIssuers but missing in TrustedPublicKeys
	cfg.Gateway.TrustedIssuers["skgate://security-authority"] = []string{"non-existent-key"}

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Blocked {
		t.Fatalf("expected blocked startup on unmapped key, got valid=%t", report.Valid)
	}

	hasKeyFinding := false
	for _, f := range report.Findings {
		if f.ControlID == "SEC-KEY-004" && f.Blocking {
			hasKeyFinding = true
			break
		}
	}
	if !hasKeyFinding {
		t.Fatalf("expected SEC-KEY-004 blocking finding, got: %+v", report.Findings)
	}
}

// Scenario 4: Disabled authorization (BLOCKED)
func TestDeploymentProfileE2E_04_DisabledAuthorizationBlocked(t *testing.T) {
	cfg, _, _, _, _, _ := createTestProductionFixtures(t)
	cfg.Enforcement.MandatoryAuthorization = false

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Blocked {
		t.Fatalf("expected blocked startup on disabled authorization, got valid=%t", report.Valid)
	}

	hasAuthFinding := false
	for _, f := range report.Findings {
		if f.ControlID == "SEC-AUTH-001" && f.Blocking {
			hasAuthFinding = true
			break
		}
	}
	if !hasAuthFinding {
		t.Fatalf("expected SEC-AUTH-001 blocking finding, got: %+v", report.Findings)
	}
}

// Scenario 5: Invalid Surface Lock (BLOCKED)
func TestDeploymentProfileE2E_05_InvalidSurfaceLockBlocked(t *testing.T) {
	cfg, tempDir, _, _, _, _ := createTestProductionFixtures(t)
	// Surface lock points to nonexistent file
	cfg.MCP.SurfaceLockPath = filepath.Join(tempDir, "missing.lock.json")

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Blocked {
		t.Fatalf("expected blocked startup on missing surface lock, got valid=%t", report.Valid)
	}

	hasLockFinding := false
	for _, f := range report.Findings {
		if f.ControlID == "SEC-LOCK-003" && f.Blocking {
			hasLockFinding = true
			break
		}
	}
	if !hasLockFinding {
		t.Fatalf("expected SEC-LOCK-003 blocking finding, got: %+v", report.Findings)
	}
}

// Scenario 6: Replay across process restart (BLOCKED by durable ledger)
func TestDeploymentProfileE2E_06_ReplayAcrossProcessRestartBlocked(t *testing.T) {
	tempDir := t.TempDir()
	durableDir := filepath.Join(tempDir, "durable-nonces")

	// Process instance 1
	ledger1, err := receipt.NewDurableNonceLedger(durableDir)
	if err != nil {
		t.Fatalf("failed to create durable nonce ledger: %v", err)
	}

	authID := "auth-e2e-001"
	nonce := "nonce-e2e-unique-001"
	now := time.Now().UTC()
	if err := ledger1.Consume(authID, nonce, now); err != nil {
		t.Fatalf("first consume should succeed, got %v", err)
	}

	// Process instance 2 (simulating restart or separate process on same host)
	ledger2, err := receipt.NewDurableNonceLedger(durableDir)
	if err != nil {
		t.Fatalf("failed to reload durable nonce ledger: %v", err)
	}

	// Replay must be rejected across restarts
	errReplay := ledger2.Consume(authID, nonce, now)
	if errReplay == nil {
		t.Fatalf("expected replay rejection across process restart, but Consume succeeded")
	}
	if !strings.Contains(errReplay.Error(), "replay attack detected") {
		t.Fatalf("expected replay error, got: %v", errReplay)
	}
}

// Scenario 7: Multi-host configuration with host-local nonce storage (BLOCKED by SEC-REPLAY-004)
func TestDeploymentProfileE2E_07_DistributedTopologyHostLocalBlocked(t *testing.T) {
	cfg, _, _, _, _, _ := createTestProductionFixtures(t)
	cfg.Topology = profile.TopologyDistributed
	cfg.Replay.Scope = receipt.ReplayScopeHostDurable // host-durable cannot satisfy distributed topology

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Blocked {
		t.Fatalf("expected blocked startup on distributed topology with host-local storage")
	}

	hasReplayFinding := false
	for _, f := range report.Findings {
		if f.ControlID == "SEC-REPLAY-004" && f.Blocking {
			hasReplayFinding = true
			break
		}
	}
	if !hasReplayFinding {
		t.Fatalf("expected SEC-REPLAY-004 blocking finding, got: %+v", report.Findings)
	}
}

// Scenario 8: Stale assurance (BLOCKED by CHECK-04 & IsOperationPermitted)
func TestDeploymentProfileE2E_08_StaleAssuranceBlocked(t *testing.T) {
	cfg, _, lockPath, _, gw, _ := createTestProductionFixtures(t)

	engine := continuous.NewEngine(func() time.Time { return time.Now().UTC() })
	subjDigest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	evidenceDigest := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	policyDigest := "1111222233334444555566667777888811112222333344445555666677778888"
	decisionID := "dec-001"

	_, err := engine.RegisterAssurance(
		continuous.AssuranceValidityConditions{
			SubjectID:             "test-subject",
			SubjectSource:         "local",
			SubjectDigest:         subjDigest,
			PolicyID:              "policy://prod-strict",
			PolicyDigest:          policyDigest,
			VerificationEnvDigest: "env-digest",
			RequiredEvidenceIDs:   []string{evidenceDigest},
			ToolSchemaDigests: map[string]string{
				"query_repo": "schema-1",
			},
		},
		evidenceDigest,
		[]skil.ControlProof{
			{
				ControlID:      "CTRL-01",
				SubjectDigest:  subjDigest,
				RequiredStages: []skil.AssuranceStage{skil.StageExpected, skil.StageEvidenceProduced},
				Evidence: []skil.AssuranceEvidence{
					{Stage: skil.StageExpected, EvidenceID: "ev-1", Digest: "dig-1"},
					{Stage: skil.StageEvidenceProduced, EvidenceID: "ev-2", Digest: "dig-2"},
				},
				Required: true,
				Complete: true,
			},
		},
		[]string{decisionID},
		nil,
	)
	if err != nil {
		t.Fatalf("failed to register assurance: %v", err)
	}

	liveCtx := profile.LiveReadinessContext{
		ContinuousEngine:    engine,
		SubjectDigest:       subjDigest,
		AssuranceEvidenceID: evidenceDigest,
		PolicyDigest:        policyDigest,
		DecisionID:          decisionID,
		Gateway:             gw,
		SurfaceLockPath:     lockPath,
		DurableNonceDir:     cfg.Replay.DurableDir,
	}

	tracker := profile.NewReadinessTracker(cfg, liveCtx)
	permitted, _ := tracker.IsOperationPermitted()
	if !permitted {
		t.Fatalf("expected operation permitted when fresh")
	}

	// Trigger drift to invalidate assurance
	engine.IngestDriftEvent(continuous.DriftEvent{
		EventID:    "drift-01",
		Kind:       continuous.DepToolSchema,
		Identity:   "query_repo",
		NewDigest:  "schema-2-modified",
		OccurredAt: time.Now().UTC(),
	})

	// Check updates state
	tracker.Check()

	permittedAfterDrift, reason := tracker.IsOperationPermitted()
	if permittedAfterDrift {
		t.Fatalf("expected operations to be blocked after assurance invalidation")
	}
	if reason == "" {
		t.Fatalf("expected non-empty reason when operation is blocked")
	}

	gateReport := profile.EvaluateReleaseGate(profile.ReleaseGateOptions{
		Config:        cfg,
		LiveReadiness: tracker,
	})
	if gateReport.Status == profile.GateStatusReady {
		t.Fatalf("expected release gate NOT_READY on stale assurance")
	}

	check04Pass := false
	for _, ch := range gateReport.Checks {
		if ch.ID == "CHECK-04-ASSURANCE-FRESHNESS" && ch.Status == profile.CheckPass {
			check04Pass = true
		}
	}
	if check04Pass {
		t.Fatalf("expected CHECK-04 to fail on stale assurance")
	}
}

// Scenario 9: Drift during execution (transitions readiness to StatusSecurityBlocked)
func TestDeploymentProfileE2E_09_DriftTransitionsToSecurityBlocked(t *testing.T) {
	cfg, _, lockPath, _, gw, _ := createTestProductionFixtures(t)

	engine := continuous.NewEngine(func() time.Time { return time.Now().UTC() })
	subjDigest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	evidenceDigest := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	policyDigest := "1111222233334444555566667777888811112222333344445555666677778888"
	decisionID := "dec-001"

	_, err := engine.RegisterAssurance(
		continuous.AssuranceValidityConditions{
			SubjectID:             "test-subject",
			SubjectSource:         "local",
			SubjectDigest:         subjDigest,
			PolicyID:              "policy://prod-strict",
			PolicyDigest:          policyDigest,
			VerificationEnvDigest: "env-digest",
			RequiredEvidenceIDs:   []string{evidenceDigest},
			ToolSchemaDigests: map[string]string{
				"query_repo": "schema-1",
			},
		},
		evidenceDigest,
		[]skil.ControlProof{
			{
				ControlID:      "CTRL-01",
				SubjectDigest:  subjDigest,
				RequiredStages: []skil.AssuranceStage{skil.StageExpected, skil.StageEvidenceProduced},
				Evidence: []skil.AssuranceEvidence{
					{Stage: skil.StageExpected, EvidenceID: "ev-1", Digest: "dig-1"},
					{Stage: skil.StageEvidenceProduced, EvidenceID: "ev-2", Digest: "dig-2"},
				},
				Required: true,
				Complete: true,
			},
		},
		[]string{decisionID},
		nil,
	)
	if err != nil {
		t.Fatalf("failed to register assurance: %v", err)
	}

	liveCtx := profile.LiveReadinessContext{
		ContinuousEngine:    engine,
		SubjectDigest:       subjDigest,
		AssuranceEvidenceID: evidenceDigest,
		PolicyDigest:        policyDigest,
		DecisionID:          decisionID,
		Gateway:             gw,
		SurfaceLockPath:     lockPath,
		DurableNonceDir:     cfg.Replay.DurableDir,
	}

	tracker := profile.NewReadinessTracker(cfg, liveCtx)

	statusBefore := tracker.Check()
	if statusBefore.Status != profile.StatusHealthy {
		t.Fatalf("expected initial healthy status, got %s", statusBefore.Status)
	}
	permitted, _ := tracker.IsOperationPermitted()
	if !permitted {
		t.Fatalf("expected operation permitted when healthy")
	}

	// Dynamic drift event arrives
	engine.IngestDriftEvent(continuous.DriftEvent{
		EventID:    "drift-dynamic-001",
		Kind:       continuous.DepToolSchema,
		Identity:   "query_repo",
		NewDigest:  "schema-tampered",
		OccurredAt: time.Now().UTC(),
	})

	statusAfter := tracker.Check()
	if statusAfter.Status != profile.StatusSecurityBlocked {
		t.Fatalf("expected StatusSecurityBlocked after drift, got %s", statusAfter.Status)
	}
	if statusAfter.SecurityReadiness {
		t.Fatalf("expected SecurityReadiness to be false after drift")
	}
	permittedAfter, reason := tracker.IsOperationPermitted()
	if permittedAfter {
		t.Fatalf("expected operations to be BLOCKED after drift")
	}
	if !strings.Contains(reason, "operation blocked") {
		t.Fatalf("expected blocking reason, got: %s", reason)
	}
}

// Scenario 10: Unavailable assurance oracle (BLOCKED)
func TestDeploymentProfileE2E_10_UnavailableAssuranceOracleBlocked(t *testing.T) {
	cfg, _, _, _, _, _ := createTestProductionFixtures(t)
	cfg.Assurance.OracleEnabled = false

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Blocked {
		t.Fatalf("expected blocked startup when assurance oracle is disabled")
	}

	hasAssureFinding := false
	for _, f := range report.Findings {
		if f.ControlID == "SEC-ASSURE-001" && f.Blocking {
			hasAssureFinding = true
			break
		}
	}
	if !hasAssureFinding {
		t.Fatalf("expected SEC-ASSURE-001 blocking finding, got: %+v", report.Findings)
	}
}

// Scenario 11: Missing signing key (BLOCKED)
func TestDeploymentProfileE2E_11_MissingSigningKeyBlocked(t *testing.T) {
	cfg, _, _, _, _, _ := createTestProductionFixtures(t)
	cfg.Gateway.TrustedPublicKeys = map[string]string{}

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Blocked {
		t.Fatalf("expected blocked startup when trusted public keys are empty")
	}

	hasKeyFinding := false
	for _, f := range report.Findings {
		if f.ControlID == "SEC-KEY-002" && f.Blocking {
			hasKeyFinding = true
			break
		}
	}
	if !hasKeyFinding {
		t.Fatalf("expected SEC-KEY-002 blocking finding, got: %+v", report.Findings)
	}
}

// Scenario 12: Unauthorized MCP tool invocation (BLOCKED)
func TestDeploymentProfileE2E_12_UnauthorizedMCPToolInvocationBlocked(t *testing.T) {
	_, _, lockPath, _, gw, _ := createTestProductionFixtures(t)

	interceptor, err := mcpinterceptor.NewInterceptor(mcpinterceptor.InterceptorOptions{
		SurfaceLockPath:    lockPath,
		Strict:             true,
		RequireSurfaceLock: true,
		MandatoryAuth:      true,
		Gateway:            gw,
	})
	if err != nil {
		t.Fatalf("failed to create interceptor: %v", err)
	}

	// Tool call without authorization token in params._meta.authorization
	unauthCall := []byte(`{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "query_repo", "arguments": {}}}` + "\n")
	var stdout bytes.Buffer
	err = interceptor.RunStream(bytes.NewReader(unauthCall), &stdout, true)
	if err != nil {
		t.Fatalf("unexpected stream read error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON-RPC response: %v\nOutput: %s", err, stdout.String())
	}

	if resp["error"] == nil {
		t.Fatalf("expected JSON-RPC error response for unauthorized tool call, got: %s", stdout.String())
	}
	errMap, _ := resp["error"].(map[string]interface{})
	errMsg, _ := errMap["message"].(string)
	if errMsg == "" {
		t.Fatalf("expected error message in response: %s", stdout.String())
	}
}

// Scenario 13: Policy downgrade attempts (BLOCKED by ValidateProfileTransition)
func TestDeploymentProfileE2E_13_PolicyDowngradeBlocked(t *testing.T) {
	err := profile.ValidateProfileTransition(profile.ProfileProduction, profile.ProfileDevelopment)
	if err == nil {
		t.Fatalf("expected error when attempting transition from production to development")
	}

	err = profile.ValidateProfileTransition(profile.ProfileProduction, profile.ProfileSecure)
	if err == nil {
		t.Fatalf("expected error when attempting transition from production to secure")
	}

	err = profile.ValidateProfileTransition(profile.ProfileSecure, profile.ProfileDevelopment)
	if err == nil {
		t.Fatalf("expected error when attempting transition from secure to development")
	}

	// Upgrades must succeed
	if err := profile.ValidateProfileTransition(profile.ProfileDevelopment, profile.ProfileSecure); err != nil {
		t.Fatalf("expected upgrade dev -> secure to be permitted, got %v", err)
	}
	if err := profile.ValidateProfileTransition(profile.ProfileSecure, profile.ProfileProduction); err != nil {
		t.Fatalf("expected upgrade secure -> prod to be permitted, got %v", err)
	}
}

// Scenario 14: Development-to-production configuration confusion (BLOCKED by SEC-PROF-001)
func TestDeploymentProfileE2E_14_DevToProdConfusionBlocked(t *testing.T) {
	cfg, _, _, _, _, _ := createTestProductionFixtures(t)
	// Profile is production, but environment is set to local dev
	cfg.Environment = "development-laptop"

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})
	if !report.Blocked {
		t.Fatalf("expected startup to be blocked on dev environment name in production profile")
	}

	hasProfFinding := false
	for _, f := range report.Findings {
		if f.ControlID == "SEC-PROF-001" && f.Blocking {
			hasProfFinding = true
			break
		}
	}
	if !hasProfFinding {
		t.Fatalf("expected SEC-PROF-001 blocking finding, got: %+v", report.Findings)
	}
}

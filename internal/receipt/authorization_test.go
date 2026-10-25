package receipt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

type testGatewayMaterial struct {
	issuerPub, runtimePub   ed25519.PublicKey
	issuerPriv, runtimePriv ed25519.PrivateKey
	issuerKeyID, rtKeyID    string
	now                     time.Time
}

func newTestGatewayMaterial(t *testing.T) testGatewayMaterial {
	t.Helper()
	iPub, iPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rPub, rPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testGatewayMaterial{
		issuerPub:   iPub,
		issuerPriv:  iPriv,
		issuerKeyID: signing.KeyID(iPub),
		runtimePub:  rPub,
		runtimePriv: rPriv,
		rtKeyID:     signing.KeyID(rPub),
		now:         time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC),
	}
}

func (m testGatewayMaterial) gateway(oracle AssuranceValidityOracle) *ExecutionGateway {
	return NewExecutionGateway(ExecutionGatewayConfig{
		RuntimeAudienceID: "runtime://skrun-prod-eu-1",
		TrustedIssuers: map[string][]string{
			"skgate://org-authority": {m.issuerKeyID},
		},
		TrustedPublicKeys: map[string]string{
			m.issuerKeyID: base64.StdEncoding.EncodeToString(m.issuerPub),
		},
		AssuranceOracle:  oracle,
		RevokedDigests:   map[string]string{},
		RevokedDecisions: map[string]string{},
		Nonces:           NewNonceLedger(),
		Now:              func() time.Time { return m.now },
	})
}

func (m testGatewayMaterial) baseRequest(workspace string) (ProtectedOperationRequest, ExecutionAuthorization) {
	args := map[string]any{"command": "git status"}
	argDigest, _ := CanonicalArgumentDigest(args)
	opID := CanonicalOperationID("commands.execute", "Bash", "git status")

	req := ProtectedOperationRequest{
		ExecutionID:        "exec-001",
		SubjectID:          "skill://repo-helper@1.0.0",
		SubjectDigest:      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		AgentID:            "agent://planner-main",
		SessionID:          "sess-100",
		ParentAgentID:      "",
		ToolOrServerID:     "Bash",
		Capability:         "commands.execute",
		Target:             "git status",
		CommandText:        "git status",
		Arguments:          args,
		ActivePolicyID:     "policy://prod-strict",
		ActivePolicyDigest: "sha256:pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp",
	}

	auth := ExecutionAuthorization{
		AuthorizationID:         "auth-001",
		SubjectID:               req.SubjectID,
		SubjectDigest:           req.SubjectDigest,
		AgentID:                 req.AgentID,
		SessionID:               req.SessionID,
		ParentAgentID:           req.ParentAgentID,
		ToolOrServerID:          req.ToolOrServerID,
		RequestedCapability:     req.Capability,
		EffectiveScope:          []string{"Bash(git:*)"},
		AllowedTargets:          []string{"git status"},
		OperationID:             opID,
		ArgumentDigest:          argDigest,
		PolicyID:                req.ActivePolicyID,
		PolicyDigest:            req.ActivePolicyDigest,
		DecisionID:              "dec-001",
		AssuranceState:          skil.AssuranceSafe,
		AssuranceEvidenceDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		IssuerID:                "skgate://org-authority",
		AudienceID:              "runtime://skrun-prod-eu-1",
		IssuedAt:                m.now.Add(-1 * time.Minute),
		ExpiresAt:               m.now.Add(5 * time.Minute),
		Nonce:                   "nonce-unique-001",
		SingleUse:               true,
	}
	_ = workspace
	return req, auth
}

func TestProofCarryingExecutionValidAndReceiptVerification(t *testing.T) {
	m := newTestGatewayMaterial(t)
	gw := m.gateway(nil)
	req, auth := m.baseRequest(t.TempDir())
	if err := auth.Sign(m.issuerPriv, m.issuerKeyID); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	rec, err := gw.AuthorizeAndExecute(
		context.Background(),
		auth,
		req,
		m.runtimePriv,
		m.rtKeyID,
		func(_ context.Context, _ ProtectedOperationRequest) (OperationExecutionResult, error) {
			return OperationExecutionResult{
				Accepted:             true,
				Enforced:             true,
				TransportStatus:      200,
				OutputBytes:          []byte("On branch main\nnothing to commit"),
				ObservedCapabilities: []string{"commands.execute"},
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("expected valid execution, got error: %v", err)
	}
	if rec.ExecutionOutcome != OutcomeExecuted || rec.EnforcementOutcome != EnforcementVerified {
		t.Fatalf("unexpected outcomes: exec=%s enforce=%s", rec.ExecutionOutcome, rec.EnforcementOutcome)
	}

	rtTrusted := map[string]string{
		m.rtKeyID: base64.StdEncoding.EncodeToString(m.runtimePub),
	}
	if err := VerifyOperationReceipt(rec, auth, rtTrusted, true); err != nil {
		t.Fatalf("VerifyOperationReceipt failed: %v", err)
	}
}

func TestProofCarryingExecutionAdversarialRejections(t *testing.T) {
	m := newTestGatewayMaterial(t)
	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name   string
		mutate func(gw *ExecutionGateway, req *ProtectedOperationRequest, auth *ExecutionAuthorization)
	}{
		{
			name: "forged_signature",
			mutate: func(_ *ExecutionGateway, _ *ProtectedOperationRequest, auth *ExecutionAuthorization) {
				_ = auth.Sign(roguePriv, m.issuerKeyID)
			},
		},
		{
			name: "unsigned_authorization",
			mutate: func(_ *ExecutionGateway, _ *ProtectedOperationRequest, auth *ExecutionAuthorization) {
				auth.Signatures = nil
			},
		},
		{
			name: "expired_authorization",
			mutate: func(_ *ExecutionGateway, _ *ProtectedOperationRequest, auth *ExecutionAuthorization) {
				auth.IssuedAt = m.now.Add(-10 * time.Minute)
				auth.ExpiresAt = m.now.Add(-1 * time.Second)
				_ = auth.Sign(m.issuerPriv, m.issuerKeyID)
			},
		},
		{
			name: "future_issued_authorization",
			mutate: func(_ *ExecutionGateway, _ *ProtectedOperationRequest, auth *ExecutionAuthorization) {
				auth.IssuedAt = m.now.Add(2 * time.Minute)
				auth.ExpiresAt = m.now.Add(10 * time.Minute)
				_ = auth.Sign(m.issuerPriv, m.issuerKeyID)
			},
		},
		{
			name: "wrong_audience",
			mutate: func(_ *ExecutionGateway, _ *ProtectedOperationRequest, auth *ExecutionAuthorization) {
				auth.AudienceID = "runtime://other-cluster"
				_ = auth.Sign(m.issuerPriv, m.issuerKeyID)
			},
		},
		{
			name: "wrong_subject_digest",
			mutate: func(_ *ExecutionGateway, req *ProtectedOperationRequest, _ *ExecutionAuthorization) {
				req.SubjectDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
			},
		},
		{
			name: "wrong_operation_target",
			mutate: func(_ *ExecutionGateway, req *ProtectedOperationRequest, _ *ExecutionAuthorization) {
				req.Target = "git push --force"
				req.CommandText = "git push --force"
			},
		},
		{
			name: "modified_arguments",
			mutate: func(_ *ExecutionGateway, req *ProtectedOperationRequest, _ *ExecutionAuthorization) {
				req.Arguments = map[string]any{"command": "git status; rm -rf /"}
			},
		},
		{
			name: "capability_escalation",
			mutate: func(_ *ExecutionGateway, req *ProtectedOperationRequest, auth *ExecutionAuthorization) {
				req.Capability = "network.outbound"
				auth.OperationID = CanonicalOperationID("network.outbound", req.ToolOrServerID, req.Target)
				_ = auth.Sign(m.issuerPriv, m.issuerKeyID)
			},
		},
		{
			name: "scope_shell_metacharacter_injection",
			mutate: func(_ *ExecutionGateway, req *ProtectedOperationRequest, auth *ExecutionAuthorization) {
				req.Target = "git status; cat /etc/passwd"
				req.CommandText = "git status; cat /etc/passwd"
				auth.AllowedTargets = []string{"*"}
				auth.OperationID = CanonicalOperationID(req.Capability, req.ToolOrServerID, req.Target)
				_ = auth.Sign(m.issuerPriv, m.issuerKeyID)
			},
		},
		{
			name: "revoked_assurance_evidence",
			mutate: func(gw *ExecutionGateway, _ *ProtectedOperationRequest, auth *ExecutionAuthorization) {
				gw.cfg.RevokedDigests[auth.AssuranceEvidenceDigest] = "compromised scanner key"
			},
		},
		{
			name: "policy_digest_changed",
			mutate: func(_ *ExecutionGateway, req *ProtectedOperationRequest, _ *ExecutionAuthorization) {
				req.ActivePolicyDigest = "sha256:newpolicy0000000000000000000000000000000000000000000000000000000"
			},
		},
		{
			name: "parent_to_child_agent_privilege_escalation",
			mutate: func(_ *ExecutionGateway, req *ProtectedOperationRequest, _ *ExecutionAuthorization) {
				// Child subagent attempts to execute using parent's authorization token
				req.AgentID = "agent://subagent-untrusted"
				req.ParentAgentID = "agent://planner-main"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw := m.gateway(nil)
			req, auth := m.baseRequest(t.TempDir())
			if err := auth.Sign(m.issuerPriv, m.issuerKeyID); err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			tc.mutate(gw, &req, &auth)

			called := false
			rec, err := gw.AuthorizeAndExecute(
				context.Background(),
				auth,
				req,
				m.runtimePriv,
				m.rtKeyID,
				func(_ context.Context, _ ProtectedOperationRequest) (OperationExecutionResult, error) {
					called = true
					return OperationExecutionResult{Accepted: true, Enforced: true}, nil
				},
			)
			if err == nil {
				t.Fatalf("expected adversarial case %s to be rejected, but it succeeded", tc.name)
			}
			if called {
				t.Fatalf("protected handler must never execute when authorization fails (%s)", tc.name)
			}
			if rec.ExecutionOutcome != OutcomeDenied || rec.EnforcementOutcome != EnforcementDenied {
				t.Fatalf("expected DENIED receipt, got exec=%s enforce=%s", rec.ExecutionOutcome, rec.EnforcementOutcome)
			}
		})
	}
}

func TestProofCarryingConcurrentReplayProtection(t *testing.T) {
	m := newTestGatewayMaterial(t)
	gw := m.gateway(nil)
	req, auth := m.baseRequest(t.TempDir())
	if err := auth.Sign(m.issuerPriv, m.issuerKeyID); err != nil {
		t.Fatal(err)
	}

	const workers = 32
	var wg sync.WaitGroup
	var successes int32
	var denials int32

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, err := gw.AuthorizeAndExecute(
				context.Background(),
				auth,
				req,
				m.runtimePriv,
				m.rtKeyID,
				func(_ context.Context, _ ProtectedOperationRequest) (OperationExecutionResult, error) {
					return OperationExecutionResult{Accepted: true, Enforced: true}, nil
				},
			)
			if err == nil {
				atomic.AddInt32(&successes, 1)
			} else {
				atomic.AddInt32(&denials, 1)
			}
		}()
	}
	wg.Wait()

	if successes != 1 || denials != workers-1 {
		t.Fatalf("single-use authorization replay race: successes=%d (want 1), denials=%d (want %d)",
			successes, denials, workers-1)
	}
}

func TestProofCarryingTOCTOUFileAndMCPSchemaProtection(t *testing.T) {
	m := newTestGatewayMaterial(t)
	gw := m.gateway(nil)
	ws := t.TempDir()

	filePath := filepath.Join(ws, "config.json")
	if err := os.WriteFile(filePath, []byte(`{"mode":"safe"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	binding, err := CaptureFileIdentity(ws, "config.json", false)
	if err != nil {
		t.Fatalf("CaptureFileIdentity failed: %v", err)
	}
	if binding.ResidualRisk == "" {
		t.Fatal("expected explicit residual risk when atomic OS handle binding is false")
	}

	req, auth := m.baseRequest(ws)
	req.Capability = "filesystem.read"
	req.ToolOrServerID = "WorkspaceRead"
	req.Target = "config.json"
	req.CommandText = "config.json"
	auth.RequestedCapability = "filesystem.read"
	auth.ToolOrServerID = "WorkspaceRead"
	auth.EffectiveScope = []string{"filesystem.read:config.json"}
	auth.AllowedTargets = []string{"config.json"}
	auth.OperationID = CanonicalOperationID("filesystem.read", "WorkspaceRead", "config.json")
	auth.FileBinding = &binding
	if err := auth.Sign(m.issuerPriv, m.issuerKeyID); err != nil {
		t.Fatal(err)
	}

	// Mutate file between authorization and execution (TOCTOU attack)
	if err := os.WriteFile(filePath, []byte(`{"mode":"pwned"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.AuthorizeAndExecute(context.Background(), auth, req, m.runtimePriv, m.rtKeyID, nil); err == nil {
		t.Fatal("expected TOCTOU file content mutation to be rejected")
	}

	// Replace file with symlink between check and use
	_ = os.Remove(filePath)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	_ = os.WriteFile(outside, []byte("secret"), 0o600)
	_ = os.Symlink(outside, filePath)
	if _, err := gw.AuthorizeAndExecute(context.Background(), auth, req, m.runtimePriv, m.rtKeyID, nil); err == nil {
		t.Fatal("expected TOCTOU symlink swap to be rejected")
	}

	// MCP tool schema drift between authorization and invocation
	approvedSchema := map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}}
	driftedSchema := map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}, "exec": map[string]any{"type": "string"}}}
	schemaDigest, err := CanonicalSchemaDigest(approvedSchema)
	if err != nil {
		t.Fatal(err)
	}

	mcpReq, mcpAuth := m.baseRequest(ws)
	mcpReq.Capability = "mcp.invoke"
	mcpReq.ToolOrServerID = "mcp://db-server"
	mcpReq.Target = "query_records"
	mcpReq.NegotiatedToolSchema = driftedSchema
	mcpAuth.RequestedCapability = "mcp.invoke"
	mcpAuth.ToolOrServerID = "mcp://db-server"
	mcpAuth.EffectiveScope = []string{"mcp.invoke:query_records"}
	mcpAuth.AllowedTargets = []string{"query_records"}
	mcpAuth.OperationID = CanonicalOperationID("mcp.invoke", "mcp://db-server", "query_records")
	mcpAuth.MCPBinding = &MCPInvocationBinding{
		ServerID:               "mcp://db-server",
		ToolName:               "query_records",
		NegotiatedSchemaDigest: schemaDigest,
		ArgumentDigest:         mcpAuth.ArgumentDigest,
	}
	if err := mcpAuth.Sign(m.issuerPriv, m.issuerKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.AuthorizeAndExecute(context.Background(), mcpAuth, mcpReq, m.runtimePriv, m.rtKeyID, nil); err == nil {
		t.Fatal("expected MCP tool schema drift to be rejected")
	}
}

func TestAuthorizationRejectsEmbeddedSecretsAndDistinguishesTransportFromEnforcement(t *testing.T) {
	m := newTestGatewayMaterial(t)
	_, auth := m.baseRequest(t.TempDir())
	auth.EffectiveScope = []string{"Authorization: Bearer sk-1234567890abcdefghijklmnop"}
	if err := auth.Sign(m.issuerPriv, m.issuerKeyID); err == nil {
		t.Fatal("expected authorization containing raw credential material to fail signing")
	}

	// Verify transport HTTP 200 without protocol Accepted/Enforced does NOT validate as enforced execution
	gw := m.gateway(nil)
	req, validAuth := m.baseRequest(t.TempDir())
	if err := validAuth.Sign(m.issuerPriv, m.issuerKeyID); err != nil {
		t.Fatal(err)
	}
	rec, err := gw.AuthorizeAndExecute(
		context.Background(),
		validAuth,
		req,
		m.runtimePriv,
		m.rtKeyID,
		func(_ context.Context, _ ProtectedOperationRequest) (OperationExecutionResult, error) {
			return OperationExecutionResult{
				Accepted:        false, // transport returned 200 OK, but runtime protocol did not acknowledge enforcement
				Enforced:        false,
				TransportStatus: 200,
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ExecutionOutcome != OutcomeAttempted {
		t.Fatalf("expected OutcomeAttempted when protocol Accepted=false, got %s", rec.ExecutionOutcome)
	}
	rtTrusted := map[string]string{
		m.rtKeyID: base64.StdEncoding.EncodeToString(m.runtimePub),
	}
	if err := VerifyOperationReceipt(rec, validAuth, rtTrusted, true); err == nil {
		t.Fatal("expected VerifyOperationReceipt(..., requireExecutedAndEnforced=true) to reject transport-only OutcomeAttempted receipt")
	}
}


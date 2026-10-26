package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/continuous"
	"github.com/domehahn/skil/internal/eval"
	"github.com/domehahn/skil/internal/mcpassure"
	"github.com/domehahn/skil/internal/mcpinterceptor"
	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/internal/runtimeproxy"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

type e2eIsolationAdapter struct {
	outputs []string
}

func (a *e2eIsolationAdapter) ID() string { return "native-test-e2e" }
func (a *e2eIsolationAdapter) Run(_ context.Context, _ eval.IsolationRequest, stdout, _ io.Writer) error {
	if len(a.outputs) == 0 {
		return fmt.Errorf("unexpected adapter invocation")
	}
	out := a.outputs[0]
	a.outputs = a.outputs[1:]
	_, err := io.WriteString(stdout, out)
	return err
}

// TestRuntimeEnforcementE2E_PositiveLifecycleAndNegativeMatrix verifies P0.1 through P0.6
// across real runtime and MCP entrypoints.
func TestRuntimeEnforcementE2E_PositiveLifecycleAndNegativeMatrix(t *testing.T) {
	ctx := context.Background()

	// 1. DETECT & VERIFY: Scan a real skill artifact on disk.
	skillDir := t.TempDir()
	skillMD := `---
name: repo-auditor
description: Read-only repository status skill
capabilities:
  commands:
    execute: true
    allow: ["git status"]
  tools:
    allow: ["Bash", "query_repo"]
---
# Repo Auditor
Inspects repository status safely.
`
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(skillMD), 0o600); err != nil {
		t.Fatal(err)
	}

	loadedArt, err := artifact.Load(skillDir, artifact.Options{})
	if err != nil {
		t.Fatalf("artifact.Load failed: %v", err)
	}

	reg := analyzer.DefaultRegistry(nil)
	scanRes, err := reg.Scan(ctx, skil.AnalysisContext{Artifact: loadedArt})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	pol := policy.Policy{Version: 1, MaximumSeverity: "HIGH"}
	polCheck := policy.Check(pol, policy.Input{Scan: scanRes})
	if polCheck.Decision != "ALLOW" {
		t.Fatalf("policy.Check failed: %#v", polCheck)
	}

	// 2. DECIDE & ATTEST: Create cryptographic keys, sign attestation, and register continuous assurance.
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimePub, runtimePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerKeyID := signing.KeyID(issuerPub)
	runtimeKeyID := signing.KeyID(runtimePub)

	att := skil.Attestation{
		Version: 1,
		Subject: skil.Subject{Name: loadedArt.Name, SHA256: loadedArt.Digest},
		Result:  skil.AttestResult{Status: skil.StatusPass},
	}
	if err := signing.SignAttestation(&att, issuerPriv, issuerKeyID); err != nil {
		t.Fatalf("SignAttestation failed: %v", err)
	}

	nowMu := sync.Mutex{}
	currentNow := time.Date(2026, 10, 26, 16, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return currentNow
	}
	advanceClock := func(d time.Duration) {
		nowMu.Lock()
		currentNow = currentNow.Add(d)
		nowMu.Unlock()
	}

	engine := continuous.NewEngine(nowFn)

	subjectID := "skill://repo-auditor@1.0.0"
	subjectDigest := "sha256:" + strings.TrimPrefix(loadedArt.Digest, "sha256:")
	policyID := "policy://strict"
	policyDigest := "sha256:pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
	assuranceDigest := "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	decisionID := "dec-e2e-001"

	mcpToolSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"repo": map[string]any{"type": "string"},
		},
	}
	mcpSchemaDigest, err := receipt.CanonicalSchemaDigest(mcpToolSchema)
	if err != nil {
		t.Fatal(err)
	}

	registerValidAssurance := func(subjDigest, polDigest, schemaDig string, decID string) {
		_, regErr := engine.RegisterAssurance(
			continuous.AssuranceValidityConditions{
				SubjectID:                 subjectID,
				SubjectSource:             "git://github.com/domehahn/skil",
				SubjectDigest:             subjDigest,
				PolicyID:                  policyID,
				PolicyDigest:              polDigest,
				ProviderIdentity:          "provider://openai-enterprise",
				ProviderConfigDigest:      "sha256:cfg-1",
				ModelIdentity:             "gpt-5-mini",
				VerificationEnvDigest:     "sha256:env-1",
				ToolSchemaDigests:         map[string]string{"query_repo": schemaDig},
				RuntimeCapabilities:       []string{"commands.execute", "mcp.invoke", "tools.call"},
				RequiredEvidenceIDs:       []string{"ev-static-1"},
				Dependencies:              []continuous.AssuranceDependency{{Kind: continuous.DepToolSchema, Identity: "query_repo", Digest: schemaDig, State: skil.EvidenceVerified}},
				IssuedAt:                  nowFn().Add(-1 * time.Minute),
				ExpiresAt:                 nowFn().Add(30 * time.Minute),
				MaxReconciliationInterval: 10 * time.Minute,
			},
			assuranceDigest,
			[]skil.ControlProof{{
				ControlID:      "ctrl.static.scan",
				SubjectDigest:  subjDigest,
				RequiredStages: []skil.AssuranceStage{skil.StageEvidenceProduced},
				Evidence: []skil.AssuranceEvidence{{
					Stage:      skil.StageEvidenceProduced,
					EvidenceID: "ev-static-1",
					Digest:     "sha256:ev1",
					Timestamp:  nowFn(),
				}},
				Required: true,
				Complete: true,
			}},
			[]string{decID},
			nil,
		)
		if regErr != nil {
			t.Fatalf("RegisterAssurance failed: %v", regErr)
		}
	}
	registerValidAssurance(subjectDigest, policyDigest, mcpSchemaDigest, decisionID)

	// Durable replay protection across process/gateway instances.
	nonceDir := filepath.Join(t.TempDir(), "durable-nonces")
	durableNonces, err := receipt.NewDurableNonceLedger(nonceDir)
	if err != nil {
		t.Fatalf("NewDurableNonceLedger failed: %v", err)
	}

	gateway := receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
		RuntimeAudienceID: "runtime://skrun-e2e-prod",
		TrustedIssuers: map[string][]string{
			"skgate://org-authority": {issuerKeyID},
		},
		TrustedPublicKeys: map[string]string{
			issuerKeyID: base64.StdEncoding.EncodeToString(issuerPub),
		},
		AssuranceOracle:  engine,
		RevokedDigests:   map[string]string{},
		RevokedDecisions: map[string]string{},
		Nonces:           durableNonces,
		Now:              nowFn,
	})

	// 3. AUTHORIZE -> ENFORCE -> EXECUTE -> RECEIPT via RuntimeProxy
	proxy := runtimeproxy.NewRuntimeProxy(runtimeproxy.RuntimeProxyConfig{
		Policy:               runtimeproxy.DefaultProxyPolicy(),
		Gateway:              gateway,
		RequireAuthorization: true,
		RuntimePrivateKey:    runtimePriv,
		RuntimeKeyID:         runtimeKeyID,
		DefaultSubjectID:     subjectID,
		DefaultSubjectDigest: subjectDigest,
		DefaultAgentID:       "agent://executor-main",
		DefaultSessionID:     "sess-e2e-1",
		ActivePolicyID:       policyID,
		ActivePolicyDigest:   policyDigest,
	})

	cmdArgs := map[string]any{"command": "git status"}
	cmdArgDigest, _ := receipt.CanonicalArgumentDigest(cmdArgs)
	cmdOpID := receipt.CanonicalOperationID("commands.execute", "Bash", "git status")

	makeCmdAuth := func(nonce string) *receipt.ExecutionAuthorization {
		a := &receipt.ExecutionAuthorization{
			AuthorizationID:         "auth-" + nonce,
			SubjectID:               subjectID,
			SubjectDigest:           subjectDigest,
			AgentID:                 "agent://executor-main",
			SessionID:               "sess-e2e-1",
			ToolOrServerID:          "Bash",
			RequestedCapability:     "commands.execute",
			EffectiveScope:          []string{"Bash(git:*)"},
			AllowedTargets:          []string{"git status"},
			OperationID:             cmdOpID,
			ArgumentDigest:          cmdArgDigest,
			PolicyID:                policyID,
			PolicyDigest:            policyDigest,
			DecisionID:              decisionID,
			AssuranceState:          skil.AssuranceSafe,
			AssuranceEvidenceDigest: assuranceDigest,
			IssuerID:                "skgate://org-authority",
			AudienceID:              "runtime://skrun-e2e-prod",
			IssuedAt:                nowFn().Add(-30 * time.Second),
			ExpiresAt:               nowFn().Add(5 * time.Minute),
			Nonce:                   nonce,
			SingleUse:               true,
		}
		if err := a.Sign(issuerPriv, issuerKeyID); err != nil {
			t.Fatal(err)
		}
		return a
	}

	validAuth := makeCmdAuth("nonce-pos-1")
	executed := false
	res, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
		ToolName:      "Bash",
		Capability:    "commands.execute",
		Target:        "git status",
		Arguments:     cmdArgs,
		Authorization: validAuth,
	}, func(_ context.Context, _ map[string]any) (receipt.OperationExecutionResult, error) {
		executed = true
		return receipt.OperationExecutionResult{
			Accepted:             true,
			Enforced:             true,
			TransportStatus:      200,
			OutputBytes:          []byte("On branch main\nnothing to commit"),
			ObservedCapabilities: []string{"commands.execute"},
		}, nil
	})
	if err != nil || !executed || res.Decision != runtimeproxy.DecisionAllow {
		t.Fatalf("positive lifecycle execution failed: err=%v executed=%v res=%#v", err, executed, res)
	}
	rtTrusted := map[string]string{runtimeKeyID: base64.StdEncoding.EncodeToString(runtimePub)}
	if err := receipt.VerifyOperationReceipt(*res.Receipt, *validAuth, rtTrusted, true); err != nil {
		t.Fatalf("VerifyOperationReceipt failed: %v", err)
	}

	// Setup MCP Interceptor with mandatory auth and Surface Lock for MCP E2E checks.
	lockDir := t.TempDir()
	lockPath := filepath.Join(lockDir, "mcp-lock.json")
	lockDoc := mcpassure.SurfaceLock{
		Version: 1,
		Tools: map[string]string{
			"query_repo": strings.TrimPrefix(mcpSchemaDigest, "sha256:"),
		},
	}
	lockBytes, _ := json.Marshal(lockDoc)
	if err := os.WriteFile(lockPath, lockBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	mcpInt, err := mcpinterceptor.NewInterceptor(mcpinterceptor.InterceptorOptions{
		SurfaceLockPath:    lockPath,
		Strict:             true,
		RequireSurfaceLock: true,
		MandatoryAuth:      true,
		Gateway:            gateway,
		ServerID:           "mcp://repo-server",
		SubjectID:          subjectID,
		SubjectDigest:      subjectDigest,
		DefaultAgentID:     "agent://executor-main",
		DefaultSessionID:   "sess-e2e-1",
		ActivePolicyID:     policyID,
		ActivePolicyDigest: policyDigest,
		LiveToolSchemas:    map[string]any{"query_repo": mcpToolSchema},
	})
	if err != nil {
		t.Fatalf("NewInterceptor failed: %v", err)
	}

	makeMCPCall := func(nonce string, mut func(*receipt.ExecutionAuthorization)) []byte {
		mArgs := map[string]any{"repo": "domehahn/skil"}
		mArgDigest, _ := receipt.CanonicalArgumentDigest(mArgs)
		mOpID := receipt.CanonicalOperationID("mcp.invoke", "mcp://repo-server", "query_repo")
		a := receipt.ExecutionAuthorization{
			AuthorizationID:         "auth-mcp-" + nonce,
			SubjectID:               subjectID,
			SubjectDigest:           subjectDigest,
			AgentID:                 "agent://executor-main",
			SessionID:               "sess-e2e-1",
			ToolOrServerID:          "mcp://repo-server",
			RequestedCapability:     "mcp.invoke",
			EffectiveScope:          []string{"mcp.invoke:query_repo"},
			AllowedTargets:          []string{"query_repo"},
			OperationID:             mOpID,
			ArgumentDigest:          mArgDigest,
			PolicyID:                policyID,
			PolicyDigest:            policyDigest,
			DecisionID:              decisionID,
			AssuranceState:          skil.AssuranceSafe,
			AssuranceEvidenceDigest: assuranceDigest,
			MCPBinding: &receipt.MCPInvocationBinding{
				ServerID:               "mcp://repo-server",
				ToolName:               "query_repo",
				NegotiatedSchemaDigest: mcpSchemaDigest,
				ArgumentDigest:         mArgDigest,
			},
			IssuerID:   "skgate://org-authority",
			AudienceID: "runtime://skrun-e2e-prod",
			IssuedAt:   nowFn().Add(-30 * time.Second),
			ExpiresAt:  nowFn().Add(5 * time.Minute),
			Nonce:      nonce,
			SingleUse:  true,
		}
		if mut != nil {
			mut(&a)
		}
		_ = a.Sign(issuerPriv, issuerKeyID)
		msg := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":                "query_repo",
				"arguments":           mArgs,
				"_skil_authorization": a,
			},
		}
		raw, _ := json.Marshal(msg)
		return raw
	}

	// Positive MCP tools/call passes interceptor and reaches upstream stream.
	var mcpUpstream bytes.Buffer
	if err := mcpInt.RunStream(bytes.NewReader(append(makeMCPCall("nonce-mcp-pos-1", nil), '\n')), &mcpUpstream, true); err != nil {
		t.Fatalf("RunStream failed: %v", err)
	}
	if !strings.Contains(mcpUpstream.String(), `"name":"query_repo"`) {
		t.Fatalf("expected authorized MCP call to be forwarded, got %q", mcpUpstream.String())
	}

	// =========================================================================
	// P0.6 — 12 Mandatory Adversarial / Negative Cases across Real Entrypoints
	// =========================================================================
	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)

	// Case 1: Missing authorization (tested on both ProcessRuntime and RuntimeProxy)
	t.Run("case_01_missing_authorization", func(t *testing.T) {
		called := false
		_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
			ToolName: "Bash", Capability: "commands.execute", Target: "git status", Arguments: cmdArgs,
		}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
			called = true
			return receipt.OperationExecutionResult{Accepted: true, Enforced: true}, nil
		})
		if err == nil || called {
			t.Fatalf("missing authorization must be rejected before execution: err=%v called=%v", err, called)
		}

		recTool := &eval.RecordedTool{Name: "Bash", Result: "ok"}
		pr := eval.ProcessRuntime{
			Executable: "/usr/bin/false", Timeout: time.Second,
			Contract: skil.SkillContract{Capabilities: skil.Capabilities{Tools: skil.ToolCapability{Allow: []string{"Bash"}}}},
			Isolation: &e2eIsolationAdapter{outputs: []string{
				`{"type":"tool_call","id":"1","tool":"Bash","arguments":{"command":"git status"}}`,
				`{"type":"final","final":{"messages":[],"tool_calls":[],"outputs":["done"],"side_effects":[],"capabilities":[],"errors":[]}}`,
			}},
			Tools:                     map[string]skil.GatewayTool{"Bash": recTool},
			ExecutionGateway:          gateway,
			RequireProofAuthorization: true,
		}
		trace, err := pr.Execute(ctx, skil.EvalRequest{
			Artifact: skil.Artifact{Name: subjectID, Digest: strings.TrimPrefix(subjectDigest, "sha256:")},
			Test:     skil.EvalSpec{Tools: skil.EvalTools{Available: []string{"Bash"}}},
		})
		if err != nil || len(recTool.Calls) != 0 || trace.ToolCalls[0].Allowed {
			t.Fatalf("ProcessRuntime executed tool without authorization: err=%v calls=%d trace=%#v", err, len(recTool.Calls), trace)
		}
	})

	// Case 2: Forged signature
	t.Run("case_02_forged_signature", func(t *testing.T) {
		auth := makeCmdAuth("nonce-neg-2")
		_ = auth.Sign(roguePriv, issuerKeyID)
		called := false
		_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
			ToolName: "Bash", Capability: "commands.execute", Target: "git status", Arguments: cmdArgs, Authorization: auth,
		}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
			called = true
			return receipt.OperationExecutionResult{}, nil
		})
		if err == nil || called {
			t.Fatal("forged signature must be rejected")
		}
	})

	// Case 3: Wrong audience
	t.Run("case_03_wrong_audience", func(t *testing.T) {
		auth := makeCmdAuth("nonce-neg-3")
		auth.AudienceID = "runtime://wrong-audience"
		_ = auth.Sign(issuerPriv, issuerKeyID)
		called := false
		_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
			ToolName: "Bash", Capability: "commands.execute", Target: "git status", Arguments: cmdArgs, Authorization: auth,
		}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
			called = true
			return receipt.OperationExecutionResult{}, nil
		})
		if err == nil || called {
			t.Fatal("wrong audience must be rejected")
		}
	})

	// Case 4: Modified arguments
	t.Run("case_04_modified_arguments", func(t *testing.T) {
		auth := makeCmdAuth("nonce-neg-4")
		called := false
		_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
			ToolName:      "Bash",
			Capability:    "commands.execute",
			Target:        "git status",
			Arguments:     map[string]any{"command": "git status; cat /etc/shadow"},
			Authorization: auth,
		}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
			called = true
			return receipt.OperationExecutionResult{}, nil
		})
		if err == nil || called {
			t.Fatal("modified arguments must be rejected")
		}
	})

	// Case 5: Expired authorization
	t.Run("case_05_expired_authorization", func(t *testing.T) {
		auth := makeCmdAuth("nonce-neg-5")
		auth.IssuedAt = nowFn().Add(-10 * time.Minute)
		auth.ExpiresAt = nowFn().Add(-1 * time.Second)
		_ = auth.Sign(issuerPriv, issuerKeyID)
		called := false
		_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
			ToolName: "Bash", Capability: "commands.execute", Target: "git status", Arguments: cmdArgs, Authorization: auth,
		}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
			called = true
			return receipt.OperationExecutionResult{}, nil
		})
		if err == nil || called {
			t.Fatal("expired authorization must be rejected")
		}
	})

	// Case 6: Replay across instances sharing durable nonce ledger
	t.Run("case_06_replay_across_durable_ledger", func(t *testing.T) {
		secondLedger, err := receipt.NewDurableNonceLedger(nonceDir)
		if err != nil {
			t.Fatal(err)
		}
		secondGateway := receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
			RuntimeAudienceID: "runtime://skrun-e2e-prod",
			TrustedIssuers:    map[string][]string{"skgate://org-authority": {issuerKeyID}},
			TrustedPublicKeys: map[string]string{issuerKeyID: base64.StdEncoding.EncodeToString(issuerPub)},
			AssuranceOracle:   engine,
			Nonces:            secondLedger,
			Now:               nowFn,
		})
		secondProxy := runtimeproxy.NewRuntimeProxy(runtimeproxy.RuntimeProxyConfig{
			Policy:               runtimeproxy.DefaultProxyPolicy(),
			Gateway:              secondGateway,
			RequireAuthorization: true,
			RuntimePrivateKey:    runtimePriv,
			RuntimeKeyID:         runtimeKeyID,
			DefaultSubjectID:     subjectID,
			DefaultSubjectDigest: subjectDigest,
			DefaultAgentID:       "agent://executor-main",
			DefaultSessionID:     "sess-e2e-1",
			ActivePolicyID:       policyID,
			ActivePolicyDigest:   policyDigest,
		})
		called := false
		// Replay validAuth ("nonce-pos-1") that was consumed on the first proxy instance!
		_, err = secondProxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
			ToolName: "Bash", Capability: "commands.execute", Target: "git status", Arguments: cmdArgs, Authorization: validAuth,
		}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
			called = true
			return receipt.OperationExecutionResult{}, nil
		})
		if err == nil || called {
			t.Fatal("cross-instance replay must be rejected by durable nonce ledger")
		}
	})

	// Case 7: Revoked assurance / decision
	t.Run("case_07_revoked_assurance", func(t *testing.T) {
		revokedDecisionID := "dec-revoked-7"
		registerValidAssurance(subjectDigest, policyDigest, mcpSchemaDigest, revokedDecisionID)
		gateway.RevokeDecision(revokedDecisionID, "security incident revocation")

		auth := makeCmdAuth("nonce-neg-7")
		auth.DecisionID = revokedDecisionID
		_ = auth.Sign(issuerPriv, issuerKeyID)

		called := false
		_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
			ToolName: "Bash", Capability: "commands.execute", Target: "git status", Arguments: cmdArgs, Authorization: auth,
		}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
			called = true
			return receipt.OperationExecutionResult{}, nil
		})
		if err == nil || called {
			t.Fatal("revoked decision must be rejected")
		}
		// Restore active assurance for subsequent tests
		registerValidAssurance(subjectDigest, policyDigest, mcpSchemaDigest, decisionID)
	})

	// Case 8: Invalid MCP schema (live schema drifted from Surface Lock / token binding)
	t.Run("case_08_invalid_mcp_schema", func(t *testing.T) {
		var out bytes.Buffer
		var errOut bytes.Buffer
		driftedInt, err := mcpinterceptor.NewInterceptor(mcpinterceptor.InterceptorOptions{
			SurfaceLockPath:    lockPath,
			Strict:             true,
			RequireSurfaceLock: true,
			MandatoryAuth:      true,
			Gateway:            gateway,
			ServerID:           "mcp://repo-server",
			SubjectID:          subjectID,
			SubjectDigest:      subjectDigest,
			DefaultAgentID:     "agent://executor-main",
			DefaultSessionID:   "sess-e2e-1",
			ActivePolicyID:     policyID,
			ActivePolicyDigest: policyDigest,
			ErrorOut:           &errOut,
			LiveToolSchemas: map[string]any{
				"query_repo": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"repo":   map[string]any{"type": "string"},
						"inject": map[string]any{"type": "string"},
					},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = driftedInt.RunStream(bytes.NewReader(append(makeMCPCall("nonce-neg-8", nil), '\n')), &out, true)
		if out.Len() != 0 {
			t.Fatalf("drifted MCP schema call must never be forwarded to upstream: %s", out.String())
		}
		if !strings.Contains(errOut.String(), "schema drifted from surface lock") {
			t.Fatalf("expected schema drift error on ErrorOut, got: %s", errOut.String())
		}
	})

	// Case 9: Malformed JSON-RPC and malformed tools/call params
	t.Run("case_09_malformed_jsonrpc", func(t *testing.T) {
		var out bytes.Buffer
		var errOut bytes.Buffer
		malformedInt, err := mcpinterceptor.NewInterceptor(mcpinterceptor.InterceptorOptions{
			SurfaceLockPath:    lockPath,
			Strict:             true,
			RequireSurfaceLock: true,
			MandatoryAuth:      true,
			Gateway:            gateway,
			ServerID:           "mcp://repo-server",
			SubjectID:          subjectID,
			SubjectDigest:      subjectDigest,
			LiveToolSchemas:    map[string]any{"query_repo": mcpToolSchema},
			ErrorOut:           &errOut,
		})
		if err != nil {
			t.Fatal(err)
		}

		malformedStream := strings.Join([]string{
			`{not-valid-json`,
			`{"jsonrpc":"1.0","id":1,"method":"tools/call"}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":"not-an-object"}`,
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_repo","arguments":"not-an-object"}}`,
		}, "\n") + "\n"

		if err := malformedInt.RunStream(strings.NewReader(malformedStream), &out, true); err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 {
			t.Fatalf("malformed JSON-RPC messages must never be forwarded to upstream server: %s", out.String())
		}
		if strings.Count(strings.TrimSpace(errOut.String()), "\n")+1 != 4 {
			t.Fatalf("expected 4 protocol-correct error responses on ErrorOut, got:\n%s", errOut.String())
		}
	})

	// Case 10: Missing required Surface Lock fails closed at startup
	t.Run("case_10_missing_required_surface_lock", func(t *testing.T) {
		if _, err := mcpinterceptor.NewInterceptor(mcpinterceptor.InterceptorOptions{
			SurfaceLockPath:    filepath.Join(t.TempDir(), "missing-lock.json"),
			RequireSurfaceLock: true,
			MandatoryAuth:      true,
			Gateway:            gateway,
		}); err == nil {
			t.Fatal("missing required Surface Lock must fail closed")
		}
	})

	// Case 11: Unauthorized subagent delegation
	t.Run("case_11_unauthorized_subagent_delegation", func(t *testing.T) {
		auth := makeCmdAuth("nonce-neg-11")
		called := false
		_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
			AgentID:       "agent://untrusted-child-subagent",
			ParentAgentID: "agent://executor-main",
			ToolName:      "Bash",
			Capability:    "commands.execute",
			Target:        "git status",
			Arguments:     cmdArgs,
			Authorization: auth,
		}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
			called = true
			return receipt.OperationExecutionResult{}, nil
		})
		if err == nil || called {
			t.Fatal("subagent attempting to reuse parent agent authorization must be rejected")
		}
	})

	// =========================================================================
	// P0.4 & Case 12 — Continuous Re-Assurance Drift Matrix & Concurrent Drift
	// =========================================================================
	t.Run("p0_4_continuous_reassurance_drift_matrix", func(t *testing.T) {
		driftScenarios := []struct {
			name    string
			trigger func()
		}{
			{
				name: "skill_mutation",
				trigger: func() {
					engine.IngestDriftEvent(continuous.DriftEvent{
						EventID: "ev-skill-mut", SubjectID: subjectID, Kind: continuous.DepSkillContentDigest,
						Identity: subjectID, NewDigest: "sha256:mutated-skill-digest", OccurredAt: nowFn(),
					})
				},
			},
			{
				name: "mcp_schema_change",
				trigger: func() {
					engine.IngestDriftEvent(continuous.DriftEvent{
						EventID: "ev-mcp-schema", SubjectID: subjectID, Kind: continuous.DepToolSchema,
						Identity: "query_repo", NewDigest: "sha256:drifted-mcp-schema", OccurredAt: nowFn(),
					})
				},
			},
			{
				name: "policy_change",
				trigger: func() {
					engine.IngestDriftEvent(continuous.DriftEvent{
						EventID: "ev-policy", Kind: continuous.DepPolicyVersion,
						Identity: policyID, NewDigest: "sha256:new-policy-digest", OccurredAt: nowFn(),
					})
				},
			},
			{
				name: "permission_escalation",
				trigger: func() {
					engine.IngestDriftEvent(continuous.DriftEvent{
						EventID: "ev-perm-esc", SubjectID: subjectID, Kind: continuous.DepRuntimeCapabilities,
						Identity: "privilege.escalate", NewDigest: "ESCALATED", OccurredAt: nowFn(),
					})
				},
			},
			{
				name: "provider_identity_change",
				trigger: func() {
					engine.IngestDriftEvent(continuous.DriftEvent{
						EventID: "ev-provider", SubjectID: subjectID, Kind: continuous.DepProviderIdentity,
						Identity: "provider://untrusted-endpoint", NewDigest: "sha256:cfg-rogue", OccurredAt: nowFn(),
					})
				},
			},
			{
				name: "revoked_evidence_via_reconcile",
				trigger: func() {
					engine.Reconcile(continuous.EnvironmentSnapshot{
						SubjectDigests: map[string]string{subjectID: subjectDigest},
						PolicyDigest:   policyDigest,
						ObservedDependencies: map[string]map[string]string{
							subjectID: {}, // required dependency evidence missing/revoked
						},
					})
				},
			},
			{
				name: "stale_reconciliation_heartbeat",
				trigger: func() {
					advanceClock(15 * time.Minute) // exceeds MaxReconciliationInterval (10m) while still within ExpiresAt (30m)
				},
			},
		}

		for i, sc := range driftScenarios {
			t.Run(sc.name, func(t *testing.T) {
				registerValidAssurance(subjectDigest, policyDigest, mcpSchemaDigest, decisionID)
				// Mint a valid token BEFORE the drift occurs.
				preIssuedAuth := makeCmdAuth(fmt.Sprintf("nonce-drift-%d", i))

				// Trigger the drift / invalidation.
				sc.trigger()

				// Attempting to execute with the previously valid token MUST fail closed.
				called := false
				_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
					ToolName: "Bash", Capability: "commands.execute",
					Target: "git status", Arguments: cmdArgs, Authorization: preIssuedAuth,
				}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
					called = true
					return receipt.OperationExecutionResult{}, nil
				})
				if err == nil || called {
					t.Fatalf("previously valid token must not authorize execution after %s", sc.name)
				}
			})
		}
	})

	// Case 12: Concurrent drift during execution
	t.Run("case_12_concurrent_drift_during_execution", func(t *testing.T) {
		registerValidAssurance(subjectDigest, policyDigest, mcpSchemaDigest, decisionID)

		const workers = 24
		tokens := make([]*receipt.ExecutionAuthorization, workers)
		for i := 0; i < workers; i++ {
			tokens[i] = makeCmdAuth(fmt.Sprintf("nonce-conc-e2e-%d", i))
		}

		var wg sync.WaitGroup
		var postDriftExecuted int32
		var driftDone atomic.Bool

		wg.Add(workers + 1)
		go func() {
			defer wg.Done()
			engine.IngestDriftEvent(continuous.DriftEvent{
				EventID: "ev-conc-12", SubjectID: subjectID, Kind: continuous.DepSkillContentDigest,
				Identity: subjectID, NewDigest: "sha256:concurrent-mutation", OccurredAt: nowFn(),
			})
			driftDone.Store(true)
		}()

		for i := 0; i < workers; i++ {
			idx := i
			go func() {
				defer wg.Done()
				wasDriftedBeforeCall := driftDone.Load()
				_, err := proxy.EnforceAndExecute(ctx, runtimeproxy.ToolCallRequest{
					ToolName: "Bash", Capability: "commands.execute",
					Target: "git status", Arguments: cmdArgs, Authorization: tokens[idx],
				}, func(context.Context, map[string]any) (receipt.OperationExecutionResult, error) {
					if wasDriftedBeforeCall {
						atomic.AddInt32(&postDriftExecuted, 1)
					}
					return receipt.OperationExecutionResult{Accepted: true, Enforced: true}, nil
				})
				if wasDriftedBeforeCall && err == nil {
					atomic.AddInt32(&postDriftExecuted, 1)
				}
			}()
		}
		wg.Wait()

		if postDriftExecuted != 0 {
			t.Fatalf("expected 0 executions after concurrent drift completion, got %d", postDriftExecuted)
		}
	})
}

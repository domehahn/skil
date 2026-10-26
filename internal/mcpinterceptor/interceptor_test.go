package mcpinterceptor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/continuous"
	"github.com/domehahn/skil/internal/mcpassure"
	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

func TestInterceptorBlocksUnauthorizedDynamicTool(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "mcp-surface.lock.json")
	lockContent := `{"version": 1, "tools": {"safe_tool": "sha256:123"}}`
	if err := os.WriteFile(lockPath, []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}

	interceptor, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath: lockPath,
		Strict:          true,
	})
	if err != nil {
		t.Fatalf("NewInterceptor failed: %v", err)
	}

	// 1. Authorized tool call
	safeCall := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool"}}`)
	res, err := interceptor.FilterMessage(safeCall, true)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(res, []byte("BLOCKED")) {
		t.Fatalf("expected safe tool call to be allowed")
	}

	// 2. Unauthorized dynamic tool call
	unauthorizedCall := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unauthorized_shell"}}`)
	res, err = interceptor.FilterMessage(unauthorizedCall, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(res, []byte("BLOCKED")) {
		t.Fatalf("expected unauthorized tool call to be blocked by interceptor")
	}
}

type mcpTestEnv struct {
	pub         ed25519.PublicKey
	priv        ed25519.PrivateKey
	keyID       string
	now         time.Time
	schema      map[string]any
	schemaHash  string
	lockPath    string
	engine      *continuous.Engine
	gateway     *receipt.ExecutionGateway
	subjectID   string
	subjectHash string
	policyID    string
	policyHash  string
	evHash      string
	decisionID  string
}

func newMCPTestEnv(t *testing.T) *mcpTestEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := signing.KeyID(pub)
	now := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)

	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"query": map[string]any{"type": "string"},
		},
	}
	schemaDigest, err := receipt.CanonicalSchemaDigest(schema)
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "mcp-surface.lock.json")
	lockObj := mcpassure.SurfaceLock{
		Version: 1,
		Tools: map[string]string{
			"query_ledger": strings.TrimPrefix(schemaDigest, "sha256:"),
		},
	}
	lockBytes, _ := json.Marshal(lockObj)
	if err := os.WriteFile(lockPath, lockBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	eng := continuous.NewEngine(func() time.Time { return now })
	subjID := "skill://ledger-assistant@1.0.0"
	subjHash := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	polID := "policy://prod-mcp-v1"
	polHash := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	evHash := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	decID := "dec-mcp-001"

	stages := []skil.AssuranceStage{skil.StageExpected, skil.StageEvidenceCommitted, skil.StageProofPersisted}
	ctrl := skil.ControlProof{
		ControlID:      "ctrl-mcp-surface",
		Analyzer:       "mcp",
		SubjectDigest:  subjHash,
		RequiredStages: stages,
		Evidence: []skil.AssuranceEvidence{
			{Stage: skil.StageExpected, EvidenceID: "e1", Digest: "sha256:1", Timestamp: now},
			{Stage: skil.StageEvidenceCommitted, EvidenceID: "e2", Digest: "sha256:2", Timestamp: now},
			{Stage: skil.StageProofPersisted, EvidenceID: "e3", Digest: "sha256:3", Timestamp: now},
		},
		Required: true,
		Complete: true,
	}
	val := continuous.AssuranceValidityConditions{
		SubjectID:                 subjID,
		SubjectSource:             "registry://internal/ledger",
		SubjectDigest:             subjHash,
		PolicyID:                  polID,
		PolicyDigest:              polHash,
		ProviderIdentity:          "openai",
		ProviderConfigDigest:      "sha256:prov1",
		ModelIdentity:             "gpt-5",
		VerificationEnvDigest:     "sha256:env1",
		ToolSchemaDigests:         map[string]string{"query_ledger": schemaDigest},
		RuntimeCapabilities:       []string{"mcp.invoke"},
		RequiredEvidenceIDs:       []string{"ev-1"},
		IssuedAt:                  now.Add(-5 * time.Minute),
		ExpiresAt:                 now.Add(1 * time.Hour),
		MaxReconciliationInterval: 10 * time.Minute,
	}
	if _, err := eng.RegisterAssurance(val, evHash, []skil.ControlProof{ctrl}, []string{decID}, nil); err != nil {
		t.Fatal(err)
	}

	gw := receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
		RuntimeAudienceID: "runtime://mcp-interceptor-prod",
		TrustedIssuers:    map[string][]string{"skgate://authority": {keyID}},
		TrustedPublicKeys: map[string]string{keyID: base64.StdEncoding.EncodeToString(pub)},
		AssuranceOracle:   eng,
		Nonces:            receipt.NewNonceLedger(),
		Now:               func() time.Time { return now },
	})

	return &mcpTestEnv{
		pub:         pub,
		priv:        priv,
		keyID:       keyID,
		now:         now,
		schema:      schema,
		schemaHash:  schemaDigest,
		lockPath:    lockPath,
		engine:      eng,
		gateway:     gw,
		subjectID:   subjID,
		subjectHash: subjHash,
		policyID:    polID,
		policyHash:  polHash,
		evHash:      evHash,
		decisionID:  decID,
	}
}

func (e *mcpTestEnv) validAuth(nonce string, args map[string]any) receipt.ExecutionAuthorization {
	argDigest, _ := receipt.CanonicalArgumentDigest(args)
	opID := receipt.CanonicalOperationID("mcp.invoke", "mcp://ledger-server", "query_ledger")
	auth := receipt.ExecutionAuthorization{
		AuthorizationID:         "auth-" + nonce,
		SubjectID:               e.subjectID,
		SubjectDigest:           e.subjectHash,
		AgentID:                 "agent://planner",
		SessionID:               "sess-mcp-1",
		ToolOrServerID:          "mcp://ledger-server",
		RequestedCapability:     "mcp.invoke",
		EffectiveScope:          []string{"mcp.invoke:query_ledger"},
		AllowedTargets:          []string{"query_ledger"},
		OperationID:             opID,
		ArgumentDigest:          argDigest,
		PolicyID:                e.policyID,
		PolicyDigest:            e.policyHash,
		DecisionID:              e.decisionID,
		AssuranceState:          skil.AssuranceSafe,
		AssuranceEvidenceDigest: e.evHash,
		IssuerID:                "skgate://authority",
		AudienceID:              "runtime://mcp-interceptor-prod",
		IssuedAt:                e.now.Add(-1 * time.Minute),
		ExpiresAt:               e.now.Add(5 * time.Minute),
		Nonce:                   nonce,
		SingleUse:               true,
		MCPBinding: &receipt.MCPInvocationBinding{
			ServerID:               "mcp://ledger-server",
			ToolName:               "query_ledger",
			NegotiatedSchemaDigest: e.schemaHash,
			ArgumentDigest:         argDigest,
		},
	}
	_ = auth.Sign(e.priv, e.keyID)
	return auth
}

func TestInterceptorHardenedMandatoryEnforcement(t *testing.T) {
	env := newMCPTestEnv(t)

	var forwardedCount atomic.Int32
	interceptor, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath:    env.lockPath,
		Strict:             true,
		RequireSurfaceLock: true,
		MandatoryAuth:      true,
		Gateway:            env.gateway,
		ServerID:           "mcp://ledger-server",
		SubjectID:          env.subjectID,
		SubjectDigest:      env.subjectHash,
		DefaultAgentID:     "agent://planner",
		DefaultSessionID:   "sess-mcp-1",
		ActivePolicyID:     env.policyID,
		ActivePolicyDigest: env.policyHash,
		LiveToolSchemas:    map[string]any{"query_ledger": env.schema},
		OnForward: func(_ context.Context, _ []byte) error {
			forwardedCount.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewInterceptor failed: %v", err)
	}

	// Positive case: valid authorized tools/call and valid non-tools/call protocol message
	args := map[string]any{"query": "SELECT balance FROM accounts WHERE id = 1"}
	validAuth := env.validAuth("nonce-pos-1", args)
	validPayload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":                "query_ledger",
			"arguments":           args,
			"_skil_authorization": validAuth,
		},
	})
	out, blocked, err := interceptor.InspectMessage(context.Background(), validPayload, true)
	if err != nil || blocked || bytes.Contains(out, []byte("BLOCKED")) {
		t.Fatalf("expected valid authorized tools/call to succeed, blocked=%v err=%v out=%s", blocked, err, string(out))
	}
	if forwardedCount.Load() != 1 {
		t.Fatalf("expected OnForward to be called once, got %d", forwardedCount.Load())
	}

	// Unrelated protocol message (tools/list) must not be rejected
	pingPayload := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	out, blocked, err = interceptor.InspectMessage(context.Background(), pingPayload, true)
	if err != nil || blocked || bytes.Contains(out, []byte("BLOCKED")) {
		t.Fatalf("expected tools/list to be allowed through, blocked=%v err=%v", blocked, err)
	}
	if forwardedCount.Load() != 2 {
		t.Fatalf("expected OnForward count=2, got %d", forwardedCount.Load())
	}

	// Now verify all negative cases never invoke OnForward!
	beforeNeg := forwardedCount.Load()

	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedAuth := env.validAuth("nonce-forged", args)
	_ = forgedAuth.Sign(roguePriv, env.keyID)

	wrongAudAuth := env.validAuth("nonce-aud", args)
	wrongAudAuth.AudienceID = "runtime://wrong-audience"
	_ = wrongAudAuth.Sign(env.priv, env.keyID)

	expiredAuth := env.validAuth("nonce-exp", args)
	expiredAuth.IssuedAt = env.now.Add(-10 * time.Minute)
	expiredAuth.ExpiresAt = env.now.Add(-1 * time.Second)
	_ = expiredAuth.Sign(env.priv, env.keyID)

	freshForModifiedArgs := env.validAuth("nonce-mod-args", args)
	freshForSubagent := env.validAuth("nonce-subagent", args)

	negCases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "malformed_json_rpc_syntax",
			payload: []byte(`{"jsonrpc":"2.0", "method": "tools/call", BROKEN`),
		},
		{
			name:    "empty_json_rpc_message",
			payload: []byte(`   `),
		},
		{
			name:    "invalid_jsonrpc_version",
			payload: []byte(`{"jsonrpc":"1.0","id":10,"method":"tools/call","params":{"name":"query_ledger"}}`),
		},
		{
			name:    "missing_method_in_client_request",
			payload: []byte(`{"jsonrpc":"2.0","id":11}`),
		},
		{
			name:    "malformed_tools_call_params_not_object",
			payload: []byte(`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":["not-an-object"]}`),
		},
		{
			name:    "malformed_tools_call_empty_tool_name",
			payload: []byte(`{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"  "}}`),
		},
		{
			name:    "malformed_tools_call_arguments_not_object",
			payload: []byte(`{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"query_ledger","arguments":"bad"}}`),
		},
		{
			name:    "missing_authorization",
			payload: []byte(`{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"query_ledger","arguments":{"query":"SELECT 1"}}}`),
		},
		{
			name:    "unknown_untrusted_tool",
			payload: []byte(`{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"rogue_exec","arguments":{}}}`),
		},
		{
			name: "forged_signature",
			payload: mustJSON(map[string]any{
				"jsonrpc": "2.0", "id": 17, "method": "tools/call",
				"params": map[string]any{"name": "query_ledger", "arguments": args, "_skil_authorization": forgedAuth},
			}),
		},
		{
			name: "wrong_audience",
			payload: mustJSON(map[string]any{
				"jsonrpc": "2.0", "id": 18, "method": "tools/call",
				"params": map[string]any{"name": "query_ledger", "arguments": args, "_skil_authorization": wrongAudAuth},
			}),
		},
		{
			name: "modified_arguments",
			payload: mustJSON(map[string]any{
				"jsonrpc": "2.0", "id": 19, "method": "tools/call",
				"params": map[string]any{
					"name":                "query_ledger",
					"arguments":           map[string]any{"query": "DROP TABLE accounts;"},
					"_skil_authorization": freshForModifiedArgs,
				},
			}),
		},
		{
			name: "expired_authorization",
			payload: mustJSON(map[string]any{
				"jsonrpc": "2.0", "id": 20, "method": "tools/call",
				"params": map[string]any{"name": "query_ledger", "arguments": args, "_skil_authorization": expiredAuth},
			}),
		},
		{
			name:    "replayed_authorization",
			payload: validPayload, // re-submitting validAuth ("nonce-pos-1") that was already consumed!
		},
		{
			name: "unauthorized_subagent_delegation",
			payload: mustJSON(map[string]any{
				"jsonrpc": "2.0", "id": 21, "method": "tools/call",
				"params": map[string]any{
					"name":                "query_ledger",
					"arguments":           args,
					"_skil_authorization": freshForSubagent,
					"_meta": map[string]any{
						"agent_id":        "subagent://untrusted-worker",
						"parent_agent_id": "agent://planner",
					},
				},
			}),
		},
	}

	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, isBlocked, err := interceptor.InspectMessage(context.Background(), tc.payload, true)
			if err != nil {
				t.Fatalf("unexpected error on %s: %v", tc.name, err)
			}
			if !isBlocked || !bytes.Contains(resp, []byte("BLOCKED")) {
				t.Fatalf("expected %s to be blocked with JSON-RPC error, got: %s", tc.name, string(resp))
			}
			if forwardedCount.Load() != beforeNeg {
				t.Fatalf("SECURITY VIOLATION: blocked case %s reached OnForward callback!", tc.name)
			}
		})
	}
}

func TestInterceptorMissingOrInvalidSurfaceLockFailsClosed(t *testing.T) {
	env := newMCPTestEnv(t)

	// 1. Missing surface lock file must fail closed in NewInterceptor when Strict or RequireSurfaceLock or MandatoryAuth is true
	if _, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath: filepath.Join(t.TempDir(), "nonexistent.lock.json"),
		Strict:          true,
	}); err == nil {
		t.Fatal("expected missing surface lock path to fail closed in Strict mode")
	}

	// 2. Corrupted JSON in surface lock file must fail closed
	corruptPath := filepath.Join(t.TempDir(), "corrupt.lock.json")
	_ = os.WriteFile(corruptPath, []byte(`{not-json`), 0o600)
	if _, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath: corruptPath,
		Strict:          true,
	}); err == nil {
		t.Fatal("expected corrupt surface lock file to fail closed in Strict mode")
	}

	// 3. Empty tools map in surface lock must fail closed
	emptyPath := filepath.Join(t.TempDir(), "empty.lock.json")
	_ = os.WriteFile(emptyPath, []byte(`{"version":1,"tools":{}}`), 0o600)
	if _, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath: emptyPath,
		MandatoryAuth:   true,
		Gateway:         env.gateway,
	}); err == nil {
		t.Fatal("expected empty surface lock tools map to fail closed in MandatoryAuth mode")
	}
}

func TestInterceptorSchemaDriftAndContinuousAssuranceInvalidation(t *testing.T) {
	env := newMCPTestEnv(t)
	args := map[string]any{"query": "SELECT 1"}

	// 1. Live tool schema drift against SurfaceLock / MCPBinding
	driftedSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"query":          map[string]any{"type": "string"},
			"injected_shell": map[string]any{"type": "string"},
		},
	}
	interceptorDrift, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath:    env.lockPath,
		Strict:             true,
		MandatoryAuth:      true,
		Gateway:            env.gateway,
		ServerID:           "mcp://ledger-server",
		LiveToolSchemas:    map[string]any{"query_ledger": driftedSchema},
		ActivePolicyID:     env.policyID,
		ActivePolicyDigest: env.policyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	auth1 := env.validAuth("nonce-schema-drift", args)
	msg1 := mustJSON(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "query_ledger", "arguments": args, "_skil_authorization": auth1},
	})
	resp, blocked, _ := interceptorDrift.InspectMessage(context.Background(), msg1, true)
	if !blocked || !bytes.Contains(resp, []byte("schema drifted")) {
		t.Fatalf("expected live schema drift to be blocked, got: %s", string(resp))
	}

	// 2. Continuous Re-Assurance invalidation (revoked / drifted assurance) blocks previously issued valid token
	interceptorValid, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath:    env.lockPath,
		Strict:             true,
		MandatoryAuth:      true,
		Gateway:            env.gateway,
		ServerID:           "mcp://ledger-server",
		LiveToolSchemas:    map[string]any{"query_ledger": env.schema},
		ActivePolicyID:     env.policyID,
		ActivePolicyDigest: env.policyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	preIssuedAuth := env.validAuth("nonce-before-drift", args)

	// Trigger skill mutation drift in continuous.Engine
	env.engine.IngestDriftEvent(continuous.DriftEvent{
		EventID:    "drift-mcp-1",
		SubjectID:  env.subjectID,
		Kind:       continuous.DepSkillContentDigest,
		Identity:   env.subjectID,
		NewDigest:  "sha256:mutated-skill-digest",
		OccurredAt: env.now,
	})

	msg2 := mustJSON(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": "query_ledger", "arguments": args, "_skil_authorization": preIssuedAuth},
	})
	resp2, blocked2, _ := interceptorValid.InspectMessage(context.Background(), msg2, true)
	if !blocked2 || !bytes.Contains(resp2, []byte("underlying assurance is no longer valid")) {
		t.Fatalf("expected pre-issued token to be rejected after continuous assurance drift, got: %s", string(resp2))
	}
}

func TestInterceptorRunStreamNeverForwardsBlockedMessagesToServer(t *testing.T) {
	env := newMCPTestEnv(t)
	args := map[string]any{"query": "SELECT 1"}
	validAuth := env.validAuth("nonce-stream-1", args)

	var serverBuf, errBuf bytes.Buffer
	interceptor, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath:    env.lockPath,
		Strict:             true,
		MandatoryAuth:      true,
		Gateway:            env.gateway,
		ServerID:           "mcp://ledger-server",
		LiveToolSchemas:    map[string]any{"query_ledger": env.schema},
		ActivePolicyID:     env.policyID,
		ActivePolicyDigest: env.policyHash,
		ErrorOut:           &errBuf,
	})
	if err != nil {
		t.Fatal(err)
	}

	validLine := mustJSON(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "query_ledger", "arguments": args, "_skil_authorization": validAuth},
	})
	unauthLine := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_ledger","arguments":{"query":"SELECT 2"}}}`)
	malformedLine := []byte(`{malformed-json`)

	streamIn := bytes.NewBuffer(nil)
	streamIn.Write(validLine)
	streamIn.WriteByte('\n')
	streamIn.Write(unauthLine)
	streamIn.WriteByte('\n')
	streamIn.Write(malformedLine)
	streamIn.WriteByte('\n')

	if err := interceptor.RunStream(streamIn, &serverBuf, true); err != nil {
		t.Fatalf("RunStream failed: %v", err)
	}

	serverLines := strings.Split(strings.TrimSpace(serverBuf.String()), "\n")
	if len(serverLines) != 1 {
		t.Fatalf("expected exactly 1 authorized message forwarded to serverOut, got %d: %s", len(serverLines), serverBuf.String())
	}
	errLines := strings.Split(strings.TrimSpace(errBuf.String()), "\n")
	if len(errLines) != 2 {
		t.Fatalf("expected 2 blocked error responses on ErrorOut, got %d: %s", len(errLines), errBuf.String())
	}
}

func TestInterceptorConcurrentDriftAndExecution(t *testing.T) {
	env := newMCPTestEnv(t)
	args := map[string]any{"query": "SELECT 1"}

	interceptor, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath:    env.lockPath,
		Strict:             true,
		MandatoryAuth:      true,
		Gateway:            env.gateway,
		ServerID:           "mcp://ledger-server",
		LiveToolSchemas:    map[string]any{"query_ledger": env.schema},
		ActivePolicyID:     env.policyID,
		ActivePolicyDigest: env.policyHash,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(16)
	for i := 0; i < 8; i++ {
		auth := env.validAuth("nonce-conc-"+string(rune('a'+i)), args)
		payload := mustJSON(map[string]any{
			"jsonrpc": "2.0", "id": i + 1, "method": "tools/call",
			"params": map[string]any{"name": "query_ledger", "arguments": args, "_skil_authorization": auth},
		})
		go func(p []byte) {
			defer wg.Done()
			_, _, _ = interceptor.InspectMessage(context.Background(), p, true)
		}(payload)
		go func(idx int) {
			defer wg.Done()
			env.engine.IngestDriftEvent(continuous.DriftEvent{
				EventID:    "drift-conc",
				SubjectID:  env.subjectID,
				Kind:       continuous.DepToolSchema,
				Identity:   "query_ledger",
				NewDigest:  "sha256:drifted",
				OccurredAt: env.now,
			})
		}(i)
	}
	wg.Wait()

	// Post-drift call must be blocked
	postAuth := env.validAuth("nonce-post-conc", args)
	postPayload := mustJSON(map[string]any{
		"jsonrpc": "2.0", "id": 99, "method": "tools/call",
		"params": map[string]any{"name": "query_ledger", "arguments": args, "_skil_authorization": postAuth},
	})
	_, blocked, _ := interceptor.InspectMessage(context.Background(), postPayload, true)
	if !blocked {
		t.Fatal("expected post-drift MCP call to be blocked")
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

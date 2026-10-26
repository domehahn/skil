package runtimeproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/continuous"
	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

func TestEvaluateToolCall_AllowAndRedact(t *testing.T) {
	ctx := context.Background()
	policy := DefaultProxyPolicy()

	req := ToolCallRequest{
		ToolName: "fetch_url",
		Arguments: map[string]interface{}{
			"url":    "https://api.github.com/repos/domehahn/skil",
			"secret": "token=ghp_1234567890abcdefghijklmnopqrst",
		},
	}

	resp := EvaluateToolCall(ctx, req, policy)
	if resp.Decision == DecisionBlock {
		t.Fatalf("expected call to be allowed/redacted, got blocked: %s", resp.Reason)
	}

	secretArg, _ := resp.SanitizedArguments["secret"].(string)
	if secretArg == "token=ghp_1234567890abcdefghijklmnopqrst" {
		t.Errorf("expected secret to be redacted, got original string")
	}
	if !resp.ArgumentsMutated {
		t.Errorf("expected ArgumentsMutated=true when PII/secret redaction modifies arguments")
	}
}

func TestEvaluateToolCall_BlockForbiddenCommand(t *testing.T) {
	ctx := context.Background()
	policy := DefaultProxyPolicy()

	req := ToolCallRequest{
		ToolName: "execute_command",
		Arguments: map[string]interface{}{
			"command": "sudo rm -rf /",
		},
	}

	resp := EvaluateToolCall(ctx, req, policy)
	if resp.Decision != DecisionBlock {
		t.Fatalf("expected forbidden command to be BLOCKED, got decision %s", resp.Decision)
	}
}

type proxyTestEnv struct {
	iPub, rPub   ed25519.PublicKey
	iPriv, rPriv ed25519.PrivateKey
	iKeyID       string
	rKeyID       string
	now          time.Time
	engine       *continuous.Engine
	gateway      *receipt.ExecutionGateway
	subjectID    string
	subjectHash  string
	policyID     string
	policyHash   string
	evHash       string
	decisionID   string
}

func newProxyTestEnv(t *testing.T) *proxyTestEnv {
	t.Helper()
	iPub, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	iKeyID := signing.KeyID(iPub)
	rKeyID := signing.KeyID(rPub)
	now := time.Date(2026, 10, 26, 2, 0, 0, 0, time.UTC)

	eng := continuous.NewEngine(func() time.Time { return now })
	subjID := "skill://github-fetcher@1.0.0"
	subjHash := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	polID := "policy://proxy-prod-v1"
	polHash := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	evHash := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	decID := "dec-proxy-001"

	stages := []skil.AssuranceStage{skil.StageExpected, skil.StageEvidenceCommitted, skil.StageProofPersisted}
	ctrl := skil.ControlProof{
		ControlID:      "ctrl-proxy-egress",
		Analyzer:       "network",
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
		SubjectSource:             "registry://internal/github-fetcher",
		SubjectDigest:             subjHash,
		PolicyID:                  polID,
		PolicyDigest:              polHash,
		ProviderIdentity:          "openai",
		ProviderConfigDigest:      "sha256:prov1",
		ModelIdentity:             "gpt-5",
		VerificationEnvDigest:     "sha256:env1",
		RuntimeCapabilities:       []string{"network.outbound", "commands.execute"},
		RequiredEvidenceIDs:       []string{"ev-1"},
		IssuedAt:                  now.Add(-5 * time.Minute),
		ExpiresAt:                 now.Add(1 * time.Hour),
		MaxReconciliationInterval: 10 * time.Minute,
	}
	if _, err := eng.RegisterAssurance(val, evHash, []skil.ControlProof{ctrl}, []string{decID}, nil); err != nil {
		t.Fatal(err)
	}

	gw := receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
		RuntimeAudienceID: "runtime://proxy-prod-1",
		TrustedIssuers:    map[string][]string{"skgate://authority": {iKeyID}},
		TrustedPublicKeys: map[string]string{iKeyID: base64.StdEncoding.EncodeToString(iPub)},
		AssuranceOracle:   eng,
		Nonces:            receipt.NewNonceLedger(),
		Now:               func() time.Time { return now },
	})

	return &proxyTestEnv{
		iPub:        iPub,
		iPriv:       iPriv,
		rPub:        rPub,
		rPriv:       rPriv,
		iKeyID:      iKeyID,
		rKeyID:      rKeyID,
		now:         now,
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

func (e *proxyTestEnv) signAuth(nonce, toolName, capName, target string, args map[string]any) *receipt.ExecutionAuthorization {
	argDigest, _ := receipt.CanonicalArgumentDigest(args)
	opID := receipt.CanonicalOperationID(capName, toolName, target)
	auth := receipt.ExecutionAuthorization{
		AuthorizationID:         "auth-" + nonce,
		SubjectID:               e.subjectID,
		SubjectDigest:           e.subjectHash,
		AgentID:                 "agent://fetcher",
		SessionID:               "sess-proxy-1",
		ToolOrServerID:          toolName,
		RequestedCapability:     capName,
		EffectiveScope:          []string{capName + ":" + target},
		AllowedTargets:          []string{target},
		OperationID:             opID,
		ArgumentDigest:          argDigest,
		PolicyID:                e.policyID,
		PolicyDigest:            e.policyHash,
		DecisionID:              e.decisionID,
		AssuranceState:          skil.AssuranceSafe,
		AssuranceEvidenceDigest: e.evHash,
		IssuerID:                "skgate://authority",
		AudienceID:              "runtime://proxy-prod-1",
		IssuedAt:                e.now.Add(-1 * time.Minute),
		ExpiresAt:               e.now.Add(5 * time.Minute),
		Nonce:                   nonce,
		SingleUse:               true,
	}
	_ = auth.Sign(e.iPriv, e.iKeyID)
	return &auth
}

func TestRuntimeProxy_GuardrailAndProofAuthorizationIntegration(t *testing.T) {
	env := newProxyTestEnv(t)
	proxy := NewRuntimeProxy(RuntimeProxyConfig{
		Policy:               DefaultProxyPolicy(),
		Gateway:              env.gateway,
		RequireAuthorization: true,
		RuntimePrivateKey:    env.rPriv,
		RuntimeKeyID:         env.rKeyID,
		DefaultSubjectID:     env.subjectID,
		DefaultSubjectDigest: env.subjectHash,
		DefaultAgentID:       "agent://fetcher",
		DefaultSessionID:     "sess-proxy-1",
		ActivePolicyID:       env.policyID,
		ActivePolicyDigest:   env.policyHash,
	})

	// 1. Valid guardrail + valid proof-carrying authorization -> executes callback and emits signed receipt
	var callbackRuns atomic.Int32
	urlTarget := "https://api.github.com/repos/domehahn/skil"
	args := map[string]any{"url": urlTarget}
	auth := env.signAuth("nonce-ok-1", "fetch_url", "network.outbound", urlTarget, args)

	resp, err := proxy.EnforceAndExecute(
		context.Background(),
		ToolCallRequest{
			ToolName:      "fetch_url",
			Arguments:     args,
			Capability:    "network.outbound",
			Target:        urlTarget,
			Authorization: auth,
		},
		func(_ context.Context, _ map[string]any) (receipt.OperationExecutionResult, error) {
			callbackRuns.Add(1)
			return receipt.OperationExecutionResult{
				Accepted:             true,
				Enforced:             true,
				TransportStatus:      200,
				OutputBytes:          []byte(`{"ok":true}`),
				ObservedCapabilities: []string{"network.outbound"},
			}, nil
		},
	)
	if err != nil || !resp.Authorized || resp.Decision != DecisionAllow {
		t.Fatalf("expected valid call to succeed, got resp=%+v err=%v", resp, err)
	}
	if callbackRuns.Load() != 1 {
		t.Fatalf("expected callback to run once, got %d", callbackRuns.Load())
	}

	// 2. Guardrail blocks (disallowed domain) EVEN WITH valid authorization -> callback never runs!
	evilURL := "https://evil.example.org/exfil"
	evilArgs := map[string]any{"url": evilURL}
	evilAuth := env.signAuth("nonce-evil-domain", "fetch_url", "network.outbound", evilURL, evilArgs)
	resp, err = proxy.EnforceAndExecute(
		context.Background(),
		ToolCallRequest{
			ToolName:      "fetch_url",
			Arguments:     evilArgs,
			Capability:    "network.outbound",
			Target:        evilURL,
			Authorization: evilAuth,
		},
		func(_ context.Context, _ map[string]any) (receipt.OperationExecutionResult, error) {
			callbackRuns.Add(1)
			return receipt.OperationExecutionResult{Accepted: true, Enforced: true}, nil
		},
	)
	if err == nil || resp.Decision != DecisionBlock {
		t.Fatalf("expected guardrail to block disallowed domain even with valid token, got %+v", resp)
	}
	if callbackRuns.Load() != 1 {
		t.Fatal("SECURITY VIOLATION: callback executed on guardrail-blocked call")
	}

	// 3. Guardrail allows, but authorization is missing / forged / replayed / wrong audience / subagent mismatch -> callback never runs!
	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	forged := env.signAuth("nonce-forged", "fetch_url", "network.outbound", urlTarget, args)
	_ = forged.Sign(roguePriv, env.iKeyID)

	wrongAud := env.signAuth("nonce-aud", "fetch_url", "network.outbound", urlTarget, args)
	wrongAud.AudienceID = "runtime://wrong"
	_ = wrongAud.Sign(env.iPriv, env.iKeyID)

	subagentToken := env.signAuth("nonce-sub", "fetch_url", "network.outbound", urlTarget, args)

	negReqs := []struct {
		name string
		req  ToolCallRequest
	}{
		{
			name: "missing_authorization",
			req:  ToolCallRequest{ToolName: "fetch_url", Arguments: args, Capability: "network.outbound", Target: urlTarget},
		},
		{
			name: "forged_signature",
			req:  ToolCallRequest{ToolName: "fetch_url", Arguments: args, Capability: "network.outbound", Target: urlTarget, Authorization: forged},
		},
		{
			name: "wrong_audience",
			req:  ToolCallRequest{ToolName: "fetch_url", Arguments: args, Capability: "network.outbound", Target: urlTarget, Authorization: wrongAud},
		},
		{
			name: "replayed_authorization",
			req:  ToolCallRequest{ToolName: "fetch_url", Arguments: args, Capability: "network.outbound", Target: urlTarget, Authorization: auth},
		},
		{
			name: "unauthorized_subagent_delegation",
			req: ToolCallRequest{
				ToolName: "fetch_url", Arguments: args, Capability: "network.outbound", Target: urlTarget,
				AgentID: "subagent://worker", ParentAgentID: "agent://fetcher", Authorization: subagentToken,
			},
		},
	}

	for _, nr := range negReqs {
		t.Run(nr.name, func(t *testing.T) {
			r, e := proxy.EnforceAndExecute(
				context.Background(),
				nr.req,
				func(_ context.Context, _ map[string]any) (receipt.OperationExecutionResult, error) {
					callbackRuns.Add(1)
					return receipt.OperationExecutionResult{Accepted: true, Enforced: true}, nil
				},
			)
			if e == nil || r.Decision != DecisionBlock || r.Authorized {
				t.Fatalf("expected %s to fail closed, got resp=%+v err=%v", nr.name, r, e)
			}
			if callbackRuns.Load() != 1 {
				t.Fatalf("SECURITY VIOLATION: callback ran on negative case %s", nr.name)
			}
		})
	}
}

func TestRuntimeProxy_SanitizationMutationRequiresReauthorizationOrRejects(t *testing.T) {
	env := newProxyTestEnv(t)
	urlTarget := "https://api.github.com/repos/domehahn/skil"
	unsanitizedArgs := map[string]any{
		"url":  urlTarget,
		"note": "contact user@example.com for details",
	}
	origAuth := env.signAuth("nonce-san-1", "fetch_url", "network.outbound", urlTarget, unsanitizedArgs)

	// Case A: Without Reauthorizer, argument mutation by PII redaction MUST reject execution
	proxyNoReauth := NewRuntimeProxy(RuntimeProxyConfig{
		Policy:               DefaultProxyPolicy(),
		Gateway:              env.gateway,
		RequireAuthorization: true,
		RuntimePrivateKey:    env.rPriv,
		RuntimeKeyID:         env.rKeyID,
		DefaultSubjectID:     env.subjectID,
		DefaultSubjectDigest: env.subjectHash,
		ActivePolicyID:       env.policyID,
		ActivePolicyDigest:   env.policyHash,
	})
	var ran atomic.Int32
	resp, err := proxyNoReauth.EnforceAndExecute(
		context.Background(),
		ToolCallRequest{
			ToolName:      "fetch_url",
			Arguments:     unsanitizedArgs,
			Capability:    "network.outbound",
			Target:        urlTarget,
			Authorization: origAuth,
		},
		func(_ context.Context, _ map[string]any) (receipt.OperationExecutionResult, error) {
			ran.Add(1)
			return receipt.OperationExecutionResult{Accepted: true, Enforced: true}, nil
		},
	)
	if err == nil || resp.Decision != DecisionBlock || ran.Load() != 0 {
		t.Fatalf("expected sanitized argument mutation without reauthorizer to be rejected, got resp=%+v err=%v ran=%d", resp, err, ran.Load())
	}

	// Case B: With explicit Reauthorizer binding the post-sanitization arguments, execution succeeds
	proxyWithReauth := NewRuntimeProxy(RuntimeProxyConfig{
		Policy:               DefaultProxyPolicy(),
		Gateway:              env.gateway,
		RequireAuthorization: true,
		RuntimePrivateKey:    env.rPriv,
		RuntimeKeyID:         env.rKeyID,
		DefaultSubjectID:     env.subjectID,
		DefaultSubjectDigest: env.subjectHash,
		ActivePolicyID:       env.policyID,
		ActivePolicyDigest:   env.policyHash,
		Reauthorizer: func(_ context.Context, _ ToolCallRequest, sanitizedArgs map[string]any, _ receipt.ExecutionAuthorization) (*receipt.ExecutionAuthorization, error) {
			return env.signAuth("nonce-san-reauthorized", "fetch_url", "network.outbound", urlTarget, sanitizedArgs), nil
		},
	})
	resp2, err2 := proxyWithReauth.EnforceAndExecute(
		context.Background(),
		ToolCallRequest{
			ToolName:      "fetch_url",
			Arguments:     unsanitizedArgs,
			Capability:    "network.outbound",
			Target:        urlTarget,
			Authorization: origAuth,
		},
		func(_ context.Context, effectiveArgs map[string]any) (receipt.OperationExecutionResult, error) {
			if effectiveArgs["note"] != "contact [REDACTED] for details" {
				t.Fatalf("expected sanitized note in execution callback, got %v", effectiveArgs["note"])
			}
			ran.Add(1)
			return receipt.OperationExecutionResult{
				Accepted:             true,
				Enforced:             true,
				TransportStatus:      200,
				ObservedCapabilities: []string{"network.outbound"},
			}, nil
		},
	)
	if err2 != nil || !resp2.Authorized || ran.Load() != 1 {
		t.Fatalf("expected reauthorized sanitized call to succeed, got resp=%+v err=%v ran=%d", resp2, err2, ran.Load())
	}
}

func TestRuntimeProxy_ConcurrentDriftAndExecution(t *testing.T) {
	env := newProxyTestEnv(t)
	proxy := NewRuntimeProxy(RuntimeProxyConfig{
		Policy:               DefaultProxyPolicy(),
		Gateway:              env.gateway,
		RequireAuthorization: true,
		RuntimePrivateKey:    env.rPriv,
		RuntimeKeyID:         env.rKeyID,
		DefaultSubjectID:     env.subjectID,
		DefaultSubjectDigest: env.subjectHash,
		ActivePolicyID:       env.policyID,
		ActivePolicyDigest:   env.policyHash,
	})
	urlTarget := "https://api.github.com/repos/domehahn/skil"
	args := map[string]any{"url": urlTarget}

	var wg sync.WaitGroup
	wg.Add(12)
	for i := 0; i < 6; i++ {
		auth := env.signAuth("nonce-pconc-"+string(rune('a'+i)), "fetch_url", "network.outbound", urlTarget, args)
		go func(a *receipt.ExecutionAuthorization) {
			defer wg.Done()
			_, _ = proxy.EnforceAndExecute(context.Background(), ToolCallRequest{
				ToolName: "fetch_url", Arguments: args, Capability: "network.outbound", Target: urlTarget, Authorization: a,
			}, nil)
		}(auth)
		go func() {
			defer wg.Done()
			env.engine.IngestDriftEvent(continuous.DriftEvent{
				EventID:    "drift-proxy-conc",
				SubjectID:  env.subjectID,
				Kind:       continuous.DepPolicyVersion,
				Identity:   env.policyID,
				NewDigest:  "sha256:new-policy",
				OccurredAt: env.now,
			})
		}()
	}
	wg.Wait()

	postAuth := env.signAuth("nonce-post-drift", "fetch_url", "network.outbound", urlTarget, args)
	var postRan atomic.Int32
	resp, err := proxy.EnforceAndExecute(context.Background(), ToolCallRequest{
		ToolName: "fetch_url", Arguments: args, Capability: "network.outbound", Target: urlTarget, Authorization: postAuth,
	}, func(_ context.Context, _ map[string]any) (receipt.OperationExecutionResult, error) {
		postRan.Add(1)
		return receipt.OperationExecutionResult{Accepted: true, Enforced: true}, nil
	})
	if err == nil || resp.Decision != DecisionBlock || postRan.Load() != 0 {
		t.Fatalf("expected post-drift proxy call to be rejected without running callback, got resp=%+v err=%v ran=%d", resp, err, postRan.Load())
	}
}

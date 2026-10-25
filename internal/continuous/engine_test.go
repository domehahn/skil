package continuous

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

func buildValidControlProof(controlID, analyzerID, subjectDigest string, now time.Time) skil.ControlProof {
	stages := []skil.AssuranceStage{skil.StageExpected, skil.StageEvidenceCommitted, skil.StageProofPersisted}
	ev := make([]skil.AssuranceEvidence, 0, len(stages))
	for _, st := range stages {
		ev = append(ev, skil.AssuranceEvidence{
			Stage:      st,
			EvidenceID: "ev:" + controlID + ":" + string(st),
			Digest:     "sha256:1234",
			Timestamp:  now,
		})
	}
	return skil.ControlProof{
		ControlID:      controlID,
		Analyzer:       analyzerID,
		SubjectDigest:  subjectDigest,
		RequiredStages: stages,
		Evidence:       ev,
		Required:       true,
		Complete:       true,
	}
}

func baseValidity(now time.Time) AssuranceValidityConditions {
	return AssuranceValidityConditions{
		SubjectID:             "skill://finance-agent@1.2.0",
		SubjectSource:         "registry://internal/finance-agent",
		SubjectDigest:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyID:              "policy://enterprise-v1",
		PolicyDigest:          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ProviderIdentity:      "openai",
		ProviderConfigDigest:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ModelIdentity:         "gpt-5-mini",
		VerificationEnvDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		ToolSchemaDigests: map[string]string{
			"mcp://ledger/read": "sha256:sc1111",
		},
		RuntimeCapabilities: []string{"filesystem.read", "mcp.invoke"},
		Dependencies: []AssuranceDependency{
			{
				Kind:       DepDependencyVersion,
				Identity:   "pypi:pydantic@2.9.0",
				Digest:     "sha256:dep1111",
				State:      skil.EvidenceVerified,
				ControlIDs: []string{"ctrl-supply-chain"},
			},
			{
				Kind:       DepRAGDataSource,
				Identity:   "rag://corp-policies",
				Digest:     "sha256:rag1111",
				State:      skil.EvidenceVerified,
				ControlIDs: []string{"ctrl-rag-integrity"},
			},
			{
				Kind:       DepMemoryState,
				Identity:   "mem://session-store",
				Digest:     "sha256:mem1111",
				State:      skil.EvidenceVerified,
				ControlIDs: []string{"ctrl-memory-safety"},
			},
		},
		RequiredEvidenceIDs:       []string{"ev-scan-1", "ev-eval-1"},
		IssuedAt:                  now,
		ExpiresAt:                 now.Add(2 * time.Hour),
		MaxReconciliationInterval: 10 * time.Minute,
	}
}

func TestContinuousReAssuranceDriftScenariosAndReconciliation(t *testing.T) {
	now := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	current := now
	eng := NewEngine(func() time.Time { return current })

	val := baseValidity(now)
	controls := []skil.ControlProof{
		buildValidControlProof("ctrl-static-ast", "python-ast", val.SubjectDigest, now),
		buildValidControlProof("ctrl-supply-chain", "deps", val.SubjectDigest, now),
		buildValidControlProof("ctrl-rag-integrity", "rag", val.SubjectDigest, now),
		buildValidControlProof("ctrl-memory-safety", "memory", val.SubjectDigest, now),
	}

	graph := &skil.EvidenceGraphSummary{}
	rec, err := eng.RegisterAssurance(val, "sha256:ev-assurance-001", controls, []string{"dec-allow-001"}, graph)
	if err != nil {
		t.Fatalf("RegisterAssurance failed: %v", err)
	}
	if rec.State != ProofValid {
		t.Fatalf("expected ProofValid, got %s (%v)", rec.State, rec.InvalidationReasons)
	}
	if rec.EvidenceGraph == nil || len(rec.EvidenceGraph.Nodes) < 4 {
		t.Fatalf("expected assurance dependencies projected into EvidenceGraphSummary, got %#v", rec.EvidenceGraph)
	}

	if ok, reason := eng.IsAssuranceValid(val.SubjectDigest, "sha256:ev-assurance-001", val.PolicyDigest, "dec-allow-001"); !ok {
		t.Fatalf("expected initial assurance to be valid, got false: %s", reason)
	}

	// Test all drift scenarios via event-driven ingestion
	driftCases := []struct {
		name  string
		event DriftEvent
	}{
		{
			name: "skill_mutation",
			event: DriftEvent{
				EventID:   "ev-1",
				SubjectID: val.SubjectID,
				Kind:      DepSkillContentDigest,
				Identity:  val.SubjectID,
				NewDigest: "sha256:mutated",
			},
		},
		{
			name: "dependency_change",
			event: DriftEvent{
				EventID:   "ev-2",
				SubjectID: val.SubjectID,
				Kind:      DepDependencyVersion,
				Identity:  "pypi:pydantic@2.9.0",
				NewDigest: "sha256:dep2222",
			},
		},
		{
			name: "mcp_schema_drift",
			event: DriftEvent{
				EventID:   "ev-3",
				SubjectID: val.SubjectID,
				Kind:      DepToolSchema,
				Identity:  "mcp://ledger/read",
				NewDigest: "sha256:sc-drifted",
			},
		},
		{
			name: "provider_switching",
			event: DriftEvent{
				EventID:   "ev-4",
				Kind:      DepProviderIdentity,
				Identity:  "anthropic",
				NewDigest: "sha256:new-provider-cfg",
			},
		},
		{
			name: "policy_update",
			event: DriftEvent{
				EventID:   "ev-5",
				Kind:      DepPolicyVersion,
				Identity:  val.PolicyID,
				NewDigest: "sha256:new-policy-digest",
			},
		},
		{
			name: "permission_escalation",
			event: DriftEvent{
				EventID:   "ev-6",
				SubjectID: val.SubjectID,
				Kind:      DepRuntimeCapabilities,
				Identity:  "commands.execute",
				NewDigest: "ESCALATED",
			},
		},
		{
			name: "rag_source_mutation",
			event: DriftEvent{
				EventID:   "ev-7",
				SubjectID: val.SubjectID,
				Kind:      DepRAGDataSource,
				Identity:  "rag://corp-policies",
				NewDigest: "sha256:rag-poisoned",
			},
		},
	}

	for _, dc := range driftCases {
		t.Run(dc.name, func(t *testing.T) {
			subEng := NewEngine(func() time.Time { return now })
			_, err := subEng.RegisterAssurance(val, "sha256:ev-assurance-001", controls, []string{"dec-allow-001"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			transitions := subEng.IngestDriftEvent(dc.event)
			if len(transitions) != 1 {
				t.Fatalf("expected 1 invalidation transition for %s, got %d", dc.name, len(transitions))
			}
			if transitions[0].RetroactivePreventionClaimed {
				t.Fatal("must never claim retroactive prevention of prior operations")
			}
			if valid, _ := subEng.IsAssuranceValid(val.SubjectDigest, "sha256:ev-assurance-001", val.PolicyDigest, "dec-allow-001"); valid {
				t.Fatalf("expected assurance to be invalid after %s", dc.name)
			}
		})
	}
}

func TestMissedEventsAndPeriodicReconciliationRecovery(t *testing.T) {
	now := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	current := now
	eng := NewEngine(func() time.Time { return current })

	val := baseValidity(now)
	controls := []skil.ControlProof{
		buildValidControlProof("ctrl-static-ast", "python-ast", val.SubjectDigest, now),
	}
	if _, err := eng.RegisterAssurance(val, "sha256:ev-001", controls, []string{"dec-1"}, nil); err != nil {
		t.Fatal(err)
	}

	// 1. Advance clock past MaxReconciliationInterval without reconciling -> must fail closed as STALE
	current = now.Add(12 * time.Minute)
	if valid, reason := eng.IsAssuranceValid(val.SubjectDigest, "sha256:ev-001", val.PolicyDigest, "dec-1"); valid {
		t.Fatalf("expected overdue reconciliation window to mark assurance stale, got valid (reason=%s)", reason)
	}

	// Re-register and test reconciliation catching a missed RAG mutation event
	current = now
	if _, err := eng.RegisterAssurance(val, "sha256:ev-001", controls, []string{"dec-1"}, nil); err != nil {
		t.Fatal(err)
	}
	snapshot := EnvironmentSnapshot{
		SubjectDigests:        map[string]string{val.SubjectID: val.SubjectDigest},
		PolicyID:              val.PolicyID,
		PolicyDigest:          val.PolicyDigest,
		ProviderIdentity:      val.ProviderIdentity,
		ProviderConfigDigest:  val.ProviderConfigDigest,
		ModelIdentity:         val.ModelIdentity,
		VerificationEnvDigest: val.VerificationEnvDigest,
		ToolSchemaDigests:     map[string]string{"mcp://ledger/read": "sha256:sc1111"},
		RuntimeCapabilities:   val.RuntimeCapabilities,
		ObservedDependencies: map[string]map[string]string{
			val.SubjectID: {
				"dependency_version:pypi:pydantic@2.9.0": "sha256:dep1111",
				"rag_data_source:rag://corp-policies":    "sha256:rag-silent-mutation",
				"memory_state:mem://session-store":       "sha256:mem1111",
			},
		},
	}
	transitions := eng.Reconcile(snapshot)
	if len(transitions) != 1 {
		t.Fatalf("expected reconciliation to catch missed RAG drift, got %d transitions", len(transitions))
	}
	if valid, _ := eng.IsAssuranceValid(val.SubjectDigest, "sha256:ev-001", val.PolicyDigest, "dec-1"); valid {
		t.Fatal("expected assurance to be invalidated by reconciliation")
	}
}

func TestSelectiveReAssuranceAndCacheIncompatibility(t *testing.T) {
	now := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	eng := NewEngine(func() time.Time { return now })

	val := baseValidity(now)
	controls := []skil.ControlProof{
		buildValidControlProof("ctrl-static-ast", "python-ast", val.SubjectDigest, now),
		buildValidControlProof("ctrl-supply-chain", "deps", val.SubjectDigest, now),
		buildValidControlProof("ctrl-rag-integrity", "rag", val.SubjectDigest, now),
		buildValidControlProof("ctrl-memory-safety", "memory", val.SubjectDigest, now),
	}
	if _, err := eng.RegisterAssurance(val, "sha256:ev-001", controls, []string{"dec-1"}, nil); err != nil {
		t.Fatal(err)
	}

	// Case 1: Only RAG data source changed -> only ctrl-rag-integrity needs re-run; static AST, supply chain, and memory safety are reused
	observedDeps := map[string]string{
		"dependency_version:pypi:pydantic@2.9.0": "sha256:dep1111",
		"rag_data_source:rag://corp-policies":    "sha256:rag-updated",
		"memory_state:mem://session-store":       "sha256:mem1111",
	}
	plan := eng.PlanSelectiveReAssurance(val.SubjectDigest, val, observedDeps)
	if plan.FullRescanRequired {
		t.Fatalf("expected selective re-assurance, got FullRescanRequired (%s)", plan.IncompatibleReason)
	}
	if len(plan.ControlsToReRun) != 1 || plan.ControlsToReRun[0] != "ctrl-rag-integrity" {
		t.Fatalf("expected only [ctrl-rag-integrity] to re-run, got %v", plan.ControlsToReRun)
	}
	if len(plan.ReusableControls) != 3 {
		t.Fatalf("expected 3 reusable controls, got %v", plan.ReusableControls)
	}

	// Case 2: Incompatible dimensions must forbid cache reuse and require full rescan
	incompatCases := []struct {
		name   string
		mutate func(c *AssuranceValidityConditions)
	}{
		{"different_subject", func(c *AssuranceValidityConditions) { c.SubjectID = "skill://other@1.0.0" }},
		{"different_source", func(c *AssuranceValidityConditions) { c.SubjectSource = "registry://untrusted/other" }},
		{"different_artifact_digest", func(c *AssuranceValidityConditions) { c.SubjectDigest = "sha256:9999" }},
		{"different_provider", func(c *AssuranceValidityConditions) { c.ProviderIdentity = "anthropic" }},
		{"different_tool_schema", func(c *AssuranceValidityConditions) {
			c.ToolSchemaDigests = map[string]string{"mcp://ledger/read": "sha256:other"}
		}},
		{"different_policy", func(c *AssuranceValidityConditions) { c.PolicyDigest = "sha256:other-policy" }},
		{"different_verification_env", func(c *AssuranceValidityConditions) { c.VerificationEnvDigest = "sha256:other-env" }},
	}

	for _, ic := range incompatCases {
		t.Run(ic.name, func(t *testing.T) {
			cand := baseValidity(now)
			ic.mutate(&cand)
			p := eng.PlanSelectiveReAssurance(val.SubjectDigest, cand, observedDeps)
			if !p.FullRescanRequired || len(p.ReusableControls) != 0 {
				t.Fatalf("expected incompatible %s to require full rescan with 0 reusable controls, got %+v", ic.name, p)
			}
		})
	}
}

func TestConcurrentDriftAndRuntimeAuthorizationIntegration(t *testing.T) {
	now := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	eng := NewEngine(func() time.Time { return now })
	val := baseValidity(now)
	controls := []skil.ControlProof{
		buildValidControlProof("ctrl-static-ast", "python-ast", val.SubjectDigest, now),
	}
	if _, err := eng.RegisterAssurance(val, "sha256:ev-001", controls, []string{"dec-001"}, nil); err != nil {
		t.Fatal(err)
	}

	iPub, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	iKeyID := signing.KeyID(iPub)
	rKeyID := signing.KeyID(rPub)

	gw := receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
		RuntimeAudienceID: "runtime://skrun-1",
		TrustedIssuers:    map[string][]string{"skgate://authority": {iKeyID}},
		TrustedPublicKeys: map[string]string{iKeyID: base64.StdEncoding.EncodeToString(iPub)},
		AssuranceOracle:   eng,
		Nonces:            receipt.NewNonceLedger(),
		Now:               func() time.Time { return now },
	})

	var wg sync.WaitGroup
	wg.Add(16)
	for i := 0; i < 8; i++ {
		go func(idx int) {
			defer wg.Done()
			args := map[string]any{"query": "select 1"}
			argDigest, _ := receipt.CanonicalArgumentDigest(args)
			opID := receipt.CanonicalOperationID("mcp.invoke", "mcp://ledger/read", "query")
			auth := receipt.ExecutionAuthorization{
				AuthorizationID:         "auth-conc-" + string(rune('a'+idx)),
				SubjectID:               val.SubjectID,
				SubjectDigest:           val.SubjectDigest,
				AgentID:                 "agent://main",
				SessionID:               "sess-1",
				ToolOrServerID:          "mcp://ledger/read",
				RequestedCapability:     "mcp.invoke",
				EffectiveScope:          []string{"mcp.invoke:query"},
				AllowedTargets:          []string{"query"},
				OperationID:             opID,
				ArgumentDigest:          argDigest,
				PolicyID:                val.PolicyID,
				PolicyDigest:            val.PolicyDigest,
				DecisionID:              "dec-001",
				AssuranceState:          skil.AssuranceSafe,
				AssuranceEvidenceDigest: "sha256:ev-001",
				IssuerID:                "skgate://authority",
				AudienceID:              "runtime://skrun-1",
				IssuedAt:                now.Add(-1 * time.Minute),
				ExpiresAt:               now.Add(5 * time.Minute),
				Nonce:                   "nonce-" + string(rune('a'+idx)),
				SingleUse:               true,
				MCPBinding: &receipt.MCPInvocationBinding{
					ServerID:               "mcp://ledger/read",
					ToolName:               "query",
					NegotiatedSchemaDigest: "sha256:sc1111",
					ArgumentDigest:         argDigest,
				},
			}
			_ = auth.Sign(iPriv, iKeyID)
			req := receipt.ProtectedOperationRequest{
				ExecutionID:          "exec-conc",
				SubjectID:            val.SubjectID,
				SubjectDigest:        val.SubjectDigest,
				AgentID:              "agent://main",
				SessionID:            "sess-1",
				ToolOrServerID:       "mcp://ledger/read",
				Capability:           "mcp.invoke",
				Target:               "query",
				Arguments:            args,
				NegotiatedToolSchema: map[string]any{"schema": "v1"},
				ActivePolicyID:       val.PolicyID,
				ActivePolicyDigest:   val.PolicyDigest,
			}
			_, _ = gw.AuthorizeAndExecute(context.Background(), auth, req, rPriv, rKeyID, nil)
		}(i)

		go func(idx int) {
			defer wg.Done()
			eng.IngestDriftEvent(DriftEvent{
				EventID:   "drift-conc",
				SubjectID: val.SubjectID,
				Kind:      DepToolSchema,
				Identity:  "mcp://ledger/read",
				NewDigest: "sha256:drifted-schema",
			})
		}(i)
	}
	wg.Wait()

	// After concurrent drift completes, any subsequent authorization must be rejected!
	if valid, _ := eng.IsAssuranceValid(val.SubjectDigest, "sha256:ev-001", val.PolicyDigest, "dec-001"); valid {
		t.Fatal("expected assurance to be invalid after concurrent drift")
	}
}

package attackpath

import (
	"context"
	"testing"

	"github.com/domehahn/skil/internal/eval"
	"github.com/domehahn/skil/pkg/skil"
)

func sampleMultiAgentPath(kind AttackScenarioKind) MultiAgentAttackPath {
	return MultiAgentAttackPath{
		PathID:       "path-" + string(kind),
		ScenarioKind: kind,
		Nodes: []GraphNode{
			{ID: "rag:docs", Type: NodeRAGSource, Label: "Untrusted RAG Corpus"},
			{ID: "agent:planner", Type: NodeAgent, Label: "Planner Agent"},
			{ID: "subagent:worker", Type: NodeSubagent, Label: "Worker Subagent"},
			{ID: "mcp:shell", Type: NodeMCPServer, Label: "Shell MCP Server"},
			{ID: "cred:token", Type: NodeCredential, Label: "Synthetic Token"},
			{ID: "ext:sink", Type: NodeExternalEndpoint, Label: "Controlled Loopback Sink"},
		},
		Edges: []GraphEdge{
			{From: "agent:planner", To: "rag:docs", Type: EdgeRetrievesFrom},
			{From: "agent:planner", To: "subagent:worker", Type: EdgeCanDelegate},
			{From: "subagent:worker", To: "cred:token", Type: EdgeCanRead},
			{From: "subagent:worker", To: "mcp:shell", Type: EdgeCanInvoke},
			{From: "mcp:shell", To: "ext:sink", Type: EdgeFlowsTo},
		},
	}
}

func TestAttackPathConfidenceStatesAndEvidenceGates(t *testing.T) {
	// 1. HYPOTHETICAL: Graph connectivity alone without static or dynamic evidence
	hyp := sampleMultiAgentPath(ScenarioAgentToAgentPropagation)
	conf, _ := EvaluatePathConfidence(hyp)
	if conf != ConfidenceHypothetical {
		t.Fatalf("expected HYPOTHETICAL for graph-only path, got %s", conf)
	}

	// 2. STATICALLY_SUPPORTED: Backed by deterministic static evidence IDs
	stat := sampleMultiAgentPath(ScenarioSensitiveDataFlow)
	stat.StaticEvidenceIDs = []string{"finding:SKIL-SEC-001", "finding:SKIL-NET-001"}
	conf, _ = EvaluatePathConfidence(stat)
	if conf != ConfidenceStaticallySupported {
		t.Fatalf("expected STATICALLY_SUPPORTED, got %s", conf)
	}

	// 3. LLM reasoning alone MUST NEVER become VERIFIED_EXPLOITABLE
	llmPath := sampleMultiAgentPath(ScenarioPromptInjectionRetrieved)
	llmPath.StaticEvidenceIDs = []string{"finding:SKIL-INJ-001"}
	llmPath.LLMProposed = true
	llmPath.VerificationEvidence = &AttackVerificationEvidence{
		LLMReasoningOnly: true,
		ActualOutcome:    AttackOutcomeExploitSucceeded,
		Complete:         true,
	}
	conf, _ = EvaluatePathConfidence(llmPath)
	if conf == ConfidenceVerifiedExploitable || conf == ConfidenceVerifiedBlocked {
		t.Fatalf("LLM reasoning alone promoted path to %s (forbidden)", conf)
	}
	if conf != ConfidenceStaticallySupported {
		t.Fatalf("expected STATICALLY_SUPPORTED when static evidence + LLM reasoning exist, got %s", conf)
	}

	// 4. INCONCLUSIVE: Dynamic run without complete external observer evidence
	inconc := sampleMultiAgentPath(ScenarioMemoryPoisoning)
	inconc.VerificationEvidence = &AttackVerificationEvidence{
		IsolationIdentity: "native-sandbox-linux",
		ActualOutcome:     AttackOutcomeInconclusive,
		Complete:          true,
	}
	conf, _ = EvaluatePathConfidence(inconc)
	if conf != ConfidenceInconclusive {
		t.Fatalf("expected INCONCLUSIVE, got %s", conf)
	}

	// 5. VERIFIED_EXPLOITABLE: Isolated execution + host-verified external observation + EXPLOIT_SUCCEEDED
	exploitable := sampleMultiAgentPath(ScenarioCapabilityEscalation)
	evExploit := AttackVerificationEvidence{
		InitialEnvStateDigest:    "sha256:init1111",
		ScenarioID:               "scen-cap-esc-001",
		ScenarioKind:             ScenarioCapabilityEscalation,
		InputArtifactDigest:      "sha256:art1111",
		AuthorizedTestScope:      "sandbox://isolated-eval-1",
		SyntheticCanaryToken:     "SYNTHETIC-CANARY-998877",
		ControlledDestination:    "loopback://127.0.0.1:18080/sink",
		ExpectedSecurityProperty: "subagent_cannot_escalate_beyond_parent_scope",
		ActualOutcome:            AttackOutcomeExploitSucceeded,
		IsolationIdentity:        "native-seatbelt-sandbox",
		Complete:                 true,
		RuntimeObservations: []eval.RuntimeObservation{
			{
				ID:                 "obs-1",
				ScenarioID:         "scen-cap-esc-001",
				PrincipalID:        "subagent:worker",
				Action:             "mcp.invoke",
				Resource:           "mcp:shell",
				Occurred:           true,
				Authorized:         false,
				ExternallyObserved: true,
				ObserverDigest:     "sha256:host-observer-1",
				RuntimeIdentity:    "isolated-process",
			},
		},
	}
	graph := &skil.EvidenceGraphSummary{}
	verifiedPath, updatedGraph, err := VerifyAttackPathInIsolation(context.Background(), exploitable, evExploit, graph)
	if err != nil {
		t.Fatalf("VerifyAttackPathInIsolation failed: %v", err)
	}
	if verifiedPath.Confidence != ConfidenceVerifiedExploitable {
		t.Fatalf("expected VERIFIED_EXPLOITABLE, got %s (%s)", verifiedPath.Confidence, verifiedPath.ConfidenceReason)
	}
	if updatedGraph == nil || updatedGraph.Digest == "" || len(updatedGraph.Nodes) == 0 {
		t.Fatalf("expected attack path linked into EvidenceGraphSummary, got %#v", updatedGraph)
	}

	// 6. VERIFIED_BLOCKED: Isolated execution + host-verified external observation + EnforcementDenied
	blocked := sampleMultiAgentPath(ScenarioPolicyBypassAttempt)
	evBlocked := evExploit
	evBlocked.ScenarioID = "scen-policy-bypass-001"
	evBlocked.ScenarioKind = ScenarioPolicyBypassAttempt
	evBlocked.ActualOutcome = AttackOutcomeBlocked
	evBlocked.EnforcementDenied = true
	evBlocked.RuntimeObservations = []eval.RuntimeObservation{
		{
			ID:                 "obs-blocked-1",
			ScenarioID:         "scen-policy-bypass-001",
			PrincipalID:        "subagent:worker",
			Action:             "mcp.invoke",
			Resource:           "mcp:shell",
			Occurred:           false,
			Authorized:         false,
			ExternallyObserved: true,
			ObserverDigest:     "sha256:host-observer-1",
			RuntimeIdentity:    "isolated-process",
		},
	}
	blockedPath, _, err := VerifyAttackPathInIsolation(context.Background(), blocked, evBlocked, updatedGraph)
	if err != nil {
		t.Fatalf("VerifyAttackPathInIsolation (blocked) failed: %v", err)
	}
	if blockedPath.Confidence != ConfidenceVerifiedBlocked {
		t.Fatalf("expected VERIFIED_BLOCKED, got %s (%s)", blockedPath.Confidence, blockedPath.ConfidenceReason)
	}
}

func TestAllTenControlledAttackScenariosAndSyntheticSafetyGuards(t *testing.T) {
	allScenarios := []AttackScenarioKind{
		ScenarioPromptInjectionRetrieved,
		ScenarioMemoryPoisoning,
		ScenarioUnauthorizedToolInvoke,
		ScenarioAgentToAgentPropagation,
		ScenarioCapabilityEscalation,
		ScenarioMCPToolMisuse,
		ScenarioSensitiveDataFlow,
		ScenarioUnsafeDelegation,
		ScenarioToolOutputLaundering,
		ScenarioPolicyBypassAttempt,
	}

	for _, kind := range allScenarios {
		p := sampleMultiAgentPath(kind)
		ev := AttackVerificationEvidence{
			InitialEnvStateDigest:    "sha256:env-" + string(kind),
			ScenarioID:               "scen-" + string(kind),
			ScenarioKind:             kind,
			InputArtifactDigest:      "sha256:art-" + string(kind),
			AuthorizedTestScope:      "sandbox://scope-" + string(kind),
			SyntheticCanaryToken:     "SYNTHETIC-CANARY-" + string(kind),
			ControlledDestination:    "controlled://sink/" + string(kind),
			ExpectedSecurityProperty: "must_block_" + string(kind),
			ActualOutcome:            AttackOutcomeBlocked,
			EnforcementDenied:        true,
			IsolationIdentity:        "native-isolation",
			Complete:                 true,
			RuntimeObservations: []eval.RuntimeObservation{
				{
					ID:                 "obs-" + string(kind),
					ScenarioID:         "scen-" + string(kind),
					PrincipalID:        "agent:planner",
					Action:             "test",
					Resource:           "res",
					ExternallyObserved: true,
					ObserverDigest:     "sha256:obs",
					RuntimeIdentity:    "isolated-process",
				},
			},
		}
		vp, _, err := VerifyAttackPathInIsolation(context.Background(), p, ev, nil)
		if err != nil {
			t.Fatalf("scenario %s failed verification: %v", kind, err)
		}
		risk := EvaluateAttackPathRisk(vp, []string{"gateway.operation-bound-auth", "mcp.surface-lock"})
		if !risk.VerifiedBlocked || risk.VerifiedExploitable {
			t.Fatalf("scenario %s expected VerifiedBlocked=true, VerifiedExploitable=false, got %+v", kind, risk)
		}
		if len(risk.VerifiedFacts) == 0 || risk.HeuristicEstimate.AdvisoryPriority != "P4" {
			t.Fatalf("scenario %s expected fact-separated risk assessment, got %+v", kind, risk)
		}
	}

	// Reject real credentials or external destinations in controlled verification
	if err := ValidateSyntheticSafety("sk-1234567890abcdefghijklmnop", "controlled://sink", "native-sandbox", "scope"); err == nil {
		t.Fatal("expected non-synthetic credential token to be rejected")
	}
	if err := ValidateSyntheticSafety("SYNTHETIC-CANARY-1", "https://evil.example.com/exfil", "native-sandbox", "scope"); err == nil {
		t.Fatal("expected external non-controlled destination to be rejected")
	}
	if err := ValidateSyntheticSafety("SYNTHETIC-CANARY-1", "controlled://sink", "host", "scope"); err == nil {
		t.Fatal("expected host non-isolated execution environment to be rejected")
	}
}

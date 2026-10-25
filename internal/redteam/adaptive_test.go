package redteam

import (
	"context"
	"testing"

	"github.com/domehahn/skil/internal/attackpath"
)

func TestAdaptiveAssuranceGenerationValidationAndFeedbackLoop(t *testing.T) {
	triggers := []AdaptiveTriggerInput{
		{Kind: TriggerNewFinding, SourceID: "SKIL-SH-001", SubjectDigest: "sha256:sub1", Capability: "commands.execute", SecurityProperty: "prop_no_shell"},
		{Kind: TriggerChangedSkill, SourceID: "diff-001", SubjectDigest: "sha256:sub1", Capability: "filesystem.write", SecurityProperty: "prop_no_write"},
		{Kind: TriggerNewMCPCapability, SourceID: "mcp-db-exec", SubjectDigest: "sha256:sub1", Capability: "mcp.invoke", SecurityProperty: "prop_mcp_lock"},
		{Kind: TriggerChangedTrustBoundary, SourceID: "delegation-1", SubjectDigest: "sha256:sub1", Capability: "agent.autonomous", SecurityProperty: "prop_boundary"},
		{Kind: TriggerThreatIntelligence, SourceID: "ti-2026-09", SubjectDigest: "sha256:sub1", Capability: "network.outbound", SecurityProperty: "prop_ti_egress"},
		{Kind: TriggerHistoricalIncident, SourceID: "inc-404", SubjectDigest: "sha256:sub1", Capability: "secrets.read", SecurityProperty: "prop_no_secret_read"},
		{Kind: TriggerFailedVerification, SourceID: "ver-fail-1", SubjectDigest: "sha256:sub1", Capability: "commands.execute", SecurityProperty: "prop_retry_verify"},
	}

	candidates := GenerateCandidateTests(triggers)
	vPath := attackpath.MultiAgentAttackPath{
		PathID:       "path-verified-1",
		ScenarioKind: attackpath.ScenarioSensitiveDataFlow,
	}
	candidates = append(candidates, GenerateCandidateFromVerifiedAttackPath(vPath, "sha256:sub1"))

	if len(candidates) != 8 {
		t.Fatalf("expected 8 deterministic candidates from all 8 trigger kinds, got %d", len(candidates))
	}

	// Ensure LLM-proposed candidate is never auto-certified on generation
	llmCand := GenerateCandidateTests([]AdaptiveTriggerInput{
		{Kind: TriggerNewFinding, SourceID: "llm-1", SubjectDigest: "sha256:sub1", LLMProposed: true},
	})[0]
	if llmCand.CertifiedCorrect {
		t.Fatal("LLM-proposed candidate must never be automatically certified correct")
	}

	// Execute closed-loop feedback
	baselineProps := []string{"prop_no_shell"}
	report := RunAdaptiveAssuranceLoop(
		context.Background(),
		candidates,
		baselineProps,
		func(_ context.Context, cand AdaptiveCandidateTest) (CandidateExecutionObservation, error) {
			switch cand.TriggerKind {
			case TriggerNewFinding, TriggerVerifiedAttackPath:
				return CandidateExecutionObservation{
					Outcome:            AdaptiveOutcomeExploitReproduced,
					ReproducibleRuns:   3,
					TotalRuns:          3,
					ExternallyObserved: true,
					ObserverDigest:     "sha256:obs-1",
					DurationMS:         12,
					EvidenceDigest:     "sha256:ev-exploit-" + cand.CandidateID,
				}, nil
			case TriggerChangedSkill, TriggerNewMCPCapability, TriggerChangedTrustBoundary:
				return CandidateExecutionObservation{
					Outcome:            AdaptiveOutcomeControlBlocked,
					ReproducibleRuns:   3,
					TotalRuns:          3,
					ExternallyObserved: true,
					ObserverDigest:     "sha256:obs-1",
					DurationMS:         10,
					EvidenceDigest:     "sha256:ev-block-" + cand.CandidateID,
				}, nil
			default:
				// Inconclusive run
				return CandidateExecutionObservation{
					Outcome:            AdaptiveOutcomeInconclusive,
					ReproducibleRuns:   1,
					TotalRuns:          3,
					ExternallyObserved: true,
					ObserverDigest:     "sha256:obs-1",
					DurationMS:         8,
				}, nil
			}
		},
	)

	if len(report.RegressionCorpus) != 2 {
		t.Fatalf("expected 2 reproduced exploits in RegressionCorpus, got %d", len(report.RegressionCorpus))
	}
	if len(report.TestedControls) != 3 {
		t.Fatalf("expected 3 verified blocked controls in TestedControls, got %d", len(report.TestedControls))
	}
	if len(report.InconclusiveTests) != 3 {
		t.Fatalf("expected 3 inconclusive tests to remain inconclusive, got %d", len(report.InconclusiveTests))
	}
	// 5 properties verified total; 1 ("prop_no_shell") was already in baseline -> CoverageDelta must be 4
	if report.Quality.CoverageDelta != 4 {
		t.Fatalf("expected CoverageDelta=4 (newly verified properties beyond baseline), got %d", report.Quality.CoverageDelta)
	}
}

func TestValidateCandidateTestRejectsUnsafeAndEscapingTests(t *testing.T) {
	base := GenerateCandidateTests([]AdaptiveTriggerInput{
		{Kind: TriggerNewFinding, SourceID: "SKIL-SH-001", SubjectDigest: "sha256:sub1", IncludeMutations: true},
	})[0]

	if err := ValidateCandidateTest(base); err != nil {
		t.Fatalf("expected baseline generated candidate to be valid, got %v", err)
	}

	badCases := []struct {
		name   string
		mutate func(c *AdaptiveCandidateTest)
	}{
		{
			name: "production_credential_in_input",
			mutate: func(c *AdaptiveCandidateTest) {
				c.Spec.Input.Message = "Authorization: Bearer sk-1234567890abcdefghijklmnop"
			},
		},
		{
			name: "missing_isolation",
			mutate: func(c *AdaptiveCandidateTest) {
				c.RequireIsolation = false
			},
		},
		{
			name: "host_isolation_mode",
			mutate: func(c *AdaptiveCandidateTest) {
				c.IsolationMode = "host"
			},
		},
		{
			name: "wildcard_target_escape",
			mutate: func(c *AdaptiveCandidateTest) {
				c.AuthorizedTargetScope = "*"
			},
		},
		{
			name: "traversal_target_escape",
			mutate: func(c *AdaptiveCandidateTest) {
				c.Spec.Containment.AllowedTargets["filesystem.read"] = []string{"../../etc/passwd"}
			},
		},
		{
			name: "dangerous_capability_grant",
			mutate: func(c *AdaptiveCandidateTest) {
				c.AllowedCapabilities = append(c.AllowedCapabilities, "runtime.escape")
			},
		},
		{
			name: "excessive_resource_limit",
			mutate: func(c *AdaptiveCandidateTest) {
				c.Limits.MaxToolCalls = 999
			},
		},
		{
			name: "unverified_cleanup",
			mutate: func(c *AdaptiveCandidateTest) {
				c.CleanupVerified = false
			},
		},
	}

	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			cand := base
			cand.Spec = base.Spec
			if base.Spec.Containment != nil {
				cont := *base.Spec.Containment
				cont.AllowedTargets = map[string][]string{"filesystem.read": {"sandbox/**"}}
				cand.Spec.Containment = &cont
			}
			cand.AllowedCapabilities = append([]string(nil), base.AllowedCapabilities...)
			tc.mutate(&cand)
			if err := ValidateCandidateTest(cand); err == nil {
				t.Fatalf("expected unsafe candidate (%s) to be rejected", tc.name)
			}
		})
	}
}


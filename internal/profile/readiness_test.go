package profile

import (
	"testing"
	"time"

	"github.com/domehahn/skil/internal/continuous"
	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/pkg/skil"
)

func TestOperationalReadiness_LivenessVsSecurityReadinessSeparation(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	engine := continuous.NewEngine(func() time.Time { return now })

	subjID := "skill://test@1.0.0"
	subjHash := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	polHash := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	evHash := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	decID := "dec-1"

	_, err := engine.RegisterAssurance(
		continuous.AssuranceValidityConditions{
			SubjectID:                 subjID,
			SubjectSource:             "git://repo",
			SubjectDigest:             subjHash,
			PolicyID:                  "policy://p1",
			PolicyDigest:              polHash,
			VerificationEnvDigest:     "sha256:env",
			RequiredEvidenceIDs:       []string{"e1"},
			IssuedAt:                  now.Add(-1 * time.Minute),
			ExpiresAt:                 now.Add(1 * time.Hour),
			MaxReconciliationInterval: 10 * time.Minute,
		},
		evHash,
		[]skil.ControlProof{{
			ControlID: "c1", SubjectDigest: subjHash, RequiredStages: []skil.AssuranceStage{skil.StageEvidenceProduced},
			Evidence: []skil.AssuranceEvidence{{Stage: skil.StageEvidenceProduced, EvidenceID: "e1", Digest: "sha256:ev", Timestamp: now}},
			Required: true, Complete: true,
		}},
		[]string{decID},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	gw := receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
		RuntimeAudienceID: "runtime://test",
		AssuranceOracle:   engine,
	})

	cfg := DefaultSecureConfig()
	tracker := NewReadinessTracker(cfg, LiveReadinessContext{
		ProcessStartedAt:    now,
		Gateway:             gw,
		ContinuousEngine:    engine,
		SubjectDigest:       subjHash,
		AssuranceEvidenceID: evHash,
		PolicyDigest:        polHash,
		DecisionID:          decID,
		Now:                 func() time.Time { return now },
	})

	// Initial state: healthy and permitted
	r := tracker.Check()
	if !r.Liveness || !r.SecurityReadiness || !r.AssuranceFreshness || r.Status != StatusHealthy {
		t.Fatalf("expected healthy initial readiness: %#v", r)
	}
	if allowed, _ := tracker.IsOperationPermitted(); !allowed {
		t.Fatal("initial operation should be permitted")
	}

	// Trigger drift: skill mutation in continuous engine
	engine.IngestDriftEvent(continuous.DriftEvent{
		EventID: "ev-1", SubjectID: subjID, Kind: continuous.DepSkillContentDigest,
		Identity: subjID, NewDigest: "sha256:drifted", OccurredAt: now,
	})

	// Recheck readiness: Process is still alive, but SecurityReadiness and AssuranceFreshness are FALSE!
	r2 := tracker.Check()
	if !r2.Liveness {
		t.Fatal("process must remain alive")
	}
	if r2.SecurityReadiness || r2.AssuranceFreshness {
		t.Fatalf("security readiness and assurance freshness must fail closed on drift: %#v", r2)
	}
	if r2.Status != StatusSecurityBlocked {
		t.Fatalf("expected StatusSecurityBlocked, got %s", r2.Status)
	}

	// New operations MUST be blocked by the security gate
	if allowed, reason := tracker.IsOperationPermitted(); allowed || reason == "" {
		t.Fatalf("expected operation to be blocked, got allowed=%t reason=%s", allowed, reason)
	}
}

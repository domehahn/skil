package telemetry

import (
	"testing"
	"time"

	"github.com/domehahn/skil/internal/trust"
)

func TestBuildTrustTraceSpan_AndExport(t *testing.T) {
	assessment := trust.TrustAssessment{
		ArtifactName: "test-skill",
		Version:      "1.0.0",
		TrustLevel:   trust.LevelTrusted,
		Timestamp:    time.Now().UTC(),
	}

	span := BuildTrustTraceSpan(assessment)
	if span.Name != "skil.trust.eval.test-skill" {
		t.Errorf("expected span name 'skil.trust.eval.test-skill', got '%s'", span.Name)
	}

	data, err := ExportTraceBatch([]OTelSpanFormat{span})
	if err != nil {
		t.Fatalf("unexpected error exporting trace batch: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("expected exported JSON data, got 0 bytes")
	}
}

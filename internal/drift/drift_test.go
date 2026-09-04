package drift

import (
	"testing"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

func TestCompareVersions_PermissionDrift(t *testing.T) {
	baseArt := &skil.Artifact{Name: "deployer", Version: "1.0.0"}
	baseAssessment := &trust.TrustAssessment{TrustScore: trust.TrustScore{Score: 90.0}}
	baseCaps := registry.CapabilityFingerprint{Permissions: []string{"cluster.read"}}

	targetArt := &skil.Artifact{Name: "deployer", Version: "1.1.0"}
	targetAssessment := &trust.TrustAssessment{TrustScore: trust.TrustScore{Score: 75.0}}
	targetCaps := registry.CapabilityFingerprint{Permissions: []string{"cluster.read", "secrets.read", "cluster.write"}}

	report := CompareVersions(baseArt, baseAssessment, baseCaps, nil, targetArt, targetAssessment, targetCaps, nil)

	if !report.HasPermissionDrift {
		t.Fatalf("Expected permission drift to be detected")
	}

	if len(report.AddedPermissions) != 2 {
		t.Errorf("Expected 2 added permissions, got %d", len(report.AddedPermissions))
	}

	if report.Decision != registry.DecisionReview {
		t.Errorf("Expected DecisionReview due to permission drift, got %s", report.Decision)
	}
}

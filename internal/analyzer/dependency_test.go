package analyzer

import (
	"context"
	"errors"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

type vulnerabilityProvider struct {
	err error
}

type reputationProvider struct{ vulnerabilityProvider }

func (reputationProvider) Reputation(context.Context, string, string) (skil.PackageReputation, error) {
	return skil.PackageReputation{Abandoned: true}, nil
}

func (v vulnerabilityProvider) ID() string { return "test-vulnerabilities" }
func (v vulnerabilityProvider) Query(context.Context, string, string, string) ([]skil.Vulnerability, error) {
	if v.err != nil {
		return nil, v.err
	}
	return []skil.Vulnerability{{ID: "GHSA-test", Summary: "known issue", Severity: skil.SeverityCritical}}, nil
}

func TestDependencyGenericTyposquatAndAbandonedDetection(t *testing.T) {
	artifact := artifactWith("requirements.txt", "reqeusts==1.0.0\n")
	findings, err := NewDependency(reputationProvider{}).Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.RuleID] = true
	}
	if !seen["SKIL-DEP-002"] || !seen["SKIL-DEP-ABANDONED"] {
		t.Fatalf("missing reputation findings: %#v", findings)
	}
}

func TestDependencyVulnerabilityProvider(t *testing.T) {
	artifact := artifactWith("requirements.txt", "demo==1.0.0\n")
	findings, err := NewDependency(vulnerabilityProvider{}).Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "SKIL-DEP-VULN" {
		t.Fatalf("%#v", findings)
	}
}

func TestDependencyProviderFailsClosed(t *testing.T) {
	artifact := artifactWith("requirements.txt", "demo==1.0.0\n")
	if _, err := NewDependency(vulnerabilityProvider{err: errors.New("offline")}).Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact}); err == nil {
		t.Fatal("expected provider failure")
	}
}

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
	return []skil.Vulnerability{{
		ID: "GHSA-test", Aliases: []string{"GO-test", "GHSA-test"},
		Summary: "known issue", Severity: skil.SeverityCritical,
	}}, nil
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
	if len(findings[0].References) != 2 || findings[0].References[0] != "GHSA-test" || findings[0].References[1] != "GO-test" {
		t.Fatalf("vulnerability references are incomplete or unstable: %#v", findings[0].References)
	}
}

func TestDependencyProviderFailsClosed(t *testing.T) {
	artifact := artifactWith("requirements.txt", "demo==1.0.0\n")
	if _, err := NewDependency(vulnerabilityProvider{err: errors.New("offline")}).Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact}); err == nil {
		t.Fatal("expected provider failure")
	}
}

func TestDiscoverDependenciesSupportsCommonLocksAndManifests(t *testing.T) {
	artifact := skil.Artifact{Files: []skil.File{
		{Path: "package-lock.json", Data: []byte(`{"packages":{"node_modules/axios":{"version":"1.7.2"}}}`)},
		{Path: "poetry.lock", Data: []byte("[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\n")},
		{Path: "Cargo.lock", Data: []byte("[[package]]\nname = \"serde\"\nversion = \"1.0.1\"\n")},
		{Path: "Gemfile.lock", Data: []byte("GEM\n  specs:\n    rack (3.0.0)\n")},
		{Path: "pom.xml", Data: []byte("<project><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.2.3</version></dependency></dependencies></project>")},
	}}
	dependencies, err := DiscoverDependencies(artifact)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, item := range dependencies {
		got[item.Ecosystem+":"+item.Name] = item.Version
	}
	for key, version := range map[string]string{
		"npm:axios": "1.7.2", "PyPI:requests": "2.32.3", "crates.io:serde": "1.0.1",
		"RubyGems:rack": "3.0.0", "Maven:org.example:demo": "1.2.3",
	} {
		if got[key] != version {
			t.Errorf("%s: got %q want %q", key, got[key], version)
		}
	}
}

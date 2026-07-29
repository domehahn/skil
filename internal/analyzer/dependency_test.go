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

type cleanVulnerabilityProvider struct{}

func (cleanVulnerabilityProvider) ID() string { return "clean-vulnerabilities" }
func (cleanVulnerabilityProvider) Query(context.Context, string, string, string) ([]skil.Vulnerability, error) {
	return nil, nil
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

func TestDependencyMaintainedReputationDoesNotFindAbandonment(t *testing.T) {
	provider := maintainedReputationProvider{}
	findings, err := NewDependency(provider).Analyze(context.Background(), skil.AnalysisContext{
		Artifact: artifactWith("requirements.txt", "requests==2.32.4\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-DEP-ABANDONED" {
			t.Fatalf("maintained dependency marked abandoned: %#v", findings)
		}
	}
}

type maintainedReputationProvider struct{ vulnerabilityProvider }

func (maintainedReputationProvider) Reputation(context.Context, string, string) (skil.PackageReputation, error) {
	return skil.PackageReputation{Abandoned: false}, nil
}

type reputationOnlyProvider struct{ reputationProvider }

func (reputationOnlyProvider) VulnerabilityEnabled() bool { return false }

func TestReputationOnlyProviderDoesNotClaimVulnerabilityCoverage(t *testing.T) {
	analyzer := NewDependency(reputationOnlyProvider{})
	for _, analysis := range analyzer.Metadata().AnalysisTypes {
		if analysis == "vulnerability" {
			t.Fatal("reputation-only provider claimed vulnerability coverage")
		}
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

func TestDependencyControlMatrixNegativeCases(t *testing.T) {
	findings, err := NewDependency(cleanVulnerabilityProvider{}).Analyze(context.Background(), skil.AnalysisContext{
		Artifact: artifactWith("requirements.txt", "requests==2.32.4\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"SKIL-DEP-001", "SKIL-DEP-002", "SKIL-DEP-VULN"} {
		if hasRule(findings, rule) {
			t.Fatalf("pinned known clean dependency produced %s: %#v", rule, findings)
		}
	}
	unpinned, err := NewDependency(nil).Analyze(context.Background(), skil.AnalysisContext{
		Artifact: artifactWith("requirements.txt", "requests\n"),
	})
	if err != nil || !hasRule(unpinned, "SKIL-DEP-001") {
		t.Fatalf("unpinned dependency was not detected: %#v %v", unpinned, err)
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

func TestPyProjectUsesStructuredPEP508Parsing(t *testing.T) {
	artifact := artifactWith("pyproject.toml", `
[project]
name = "metadata-is-not-a-dependency"
version = "1.2.3"
dependencies = [
  "requests==2.32.4",
  "reqeusts[security]>=1.0; python_version < '3.13'",
  "python_dateutil==2.9.0",
  "demo @ https://example.invalid/demo.whl",
]

[tool.poetry.dependencies]
python = "^3.12"
flask = { version = "3.1.0", extras = ["async"] }
`)
	records, err := DiscoverDependencies(artifact)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]DependencyRecord{}
	for _, record := range records {
		byName[record.Name] = record
	}
	if len(records) != 5 {
		t.Fatalf("unexpected dependency inventory: %#v", records)
	}
	if _, found := byName["metadata-is-not-a-dependency"]; found {
		t.Fatal("project metadata was parsed as a dependency")
	}
	if got := byName["reqeusts"]; got.Version != ">=1.0" || got.Marker != "python_version < '3.13'" ||
		len(got.Extras) != 1 || got.Extras[0] != "security" {
		t.Fatalf("PEP 508 fields lost: %#v", got)
	}
	if got := byName["demo"].URL; got != "https://example.invalid/demo.whl" {
		t.Fatalf("direct URL lost: %q", got)
	}
	if got := byName["flask"].Version; got != "3.1.0" {
		t.Fatalf("Poetry version lost: %q", got)
	}
}

func TestPyPINormalizationPreservesTyposquatSignalWithoutSeparatorFalsePositives(t *testing.T) {
	for _, requirement := range []string{"requests==2.32.4", "python-dateutil==2.9.0", "python_dateutil==2.9.0"} {
		findings, err := NewDependency(nil).Analyze(context.Background(), skil.AnalysisContext{
			Artifact: artifactWith("requirements.txt", requirement+"\n"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if hasRule(findings, "SKIL-DEP-002") {
			t.Fatalf("%q produced a typosquat false positive: %#v", requirement, findings)
		}
	}
	findings, err := NewDependency(nil).Analyze(context.Background(), skil.AnalysisContext{
		Artifact: artifactWith("pyproject.toml", "[project]\ndependencies = [\"requsets>=2; python_version > '3.10'\"]\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-DEP-002") {
		t.Fatalf("PEP 508 typo was not detected: %#v", findings)
	}
}

package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestDependencySourceDetectsUntrustedNpmrcRegistry(t *testing.T) {
	analyzer := NewDependencySource()

	artifact := skil.Artifact{
		Name: "untrusted-registry-skill",
		Files: []skil.File{
			{
				Path: ".npmrc",
				Data: []byte("registry=https://evil-registry.example.com/npm/\n"),
			},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected SKIL-DEP-SOURCE-OVERRIDE finding, got none")
	}

	if findings[0].RuleID != RuleDependencySourceOverride {
		t.Fatalf("unexpected rule ID: %s", findings[0].RuleID)
	}
}

func TestDependencySourceObservesOfficialAndScopedNpmRegistries(t *testing.T) {
	artifact := skil.Artifact{Name: "npm", Files: []skil.File{{Path: ".npmrc", Data: []byte("registry=https://registry.npmjs.org\n@corp:registry=https://Packages.Example.test:443/npm/\n")}}}
	findings, observations, err := NewDependencySource().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 || observations[0].Capability != "dependency.source" {
		t.Fatalf("expected two normalized source observations: %#v", observations)
	}
	if len(findings) != 1 || findings[0].RuleID != RuleDependencySourceOverride {
		t.Fatalf("only the unknown private registry should require review: %#v", findings)
	}
	var scoped *skil.CapabilityObservation
	for index := range observations {
		if observations[index].Evidence["package"] == "@corp" {
			scoped = &observations[index]
		}
	}
	if scoped == nil || scoped.Value != "https://packages.example.test/npm/" {
		t.Fatalf("scope or URL was not canonicalized: %#v", observations)
	}
}

func TestDependencySourceParsesPipFlagsAndExtraIndex(t *testing.T) {
	artifact := skil.Artifact{Name: "pip", Files: []skil.File{
		{Path: "pip.conf", Data: []byte("[global]\nextra-index-url = https://packages.example.test/pypi\n")},
		{Path: "install.sh", Data: []byte("pip install --index-url https://pypi.org/simple pkg\n")},
	}}
	_, observations, err := NewDependencySource().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil || len(observations) != 2 {
		t.Fatalf("expected pip config and CLI observations, got %#v, %v", observations, err)
	}
}

func TestDependencySourceDetectsCargoReplacement(t *testing.T) {
	artifact := skil.Artifact{Name: "cargo", Files: []skil.File{{Path: ".cargo/config.toml", Data: []byte(`[source.crates-io]
replace-with = "company"
[source.company]
registry = "https://packages.example.test/cargo"
`)}}}
	findings, observations, err := NewDependencySource().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) < 1 || !hasDependencyRule(findings, RuleDependencySourceRedirect) {
		t.Fatalf("cargo replacement was not normalized and flagged: findings=%#v observations=%#v", findings, observations)
	}
}

func TestNormalizeRegistryURLRejectsBypasses(t *testing.T) {
	canonical, err := NormalizeRegistryURL("https://REGISTRY.NPMJS.ORG:443/a/../")
	if err != nil || canonical != "https://registry.npmjs.org/" {
		t.Fatalf("unexpected canonical URL %q: %v", canonical, err)
	}
	for _, invalid := range []string{"http://registry.npmjs.org/", "https://user@registry.npmjs.org/", "https://registry.npmjs.org/?mirror=evil"} {
		if _, err := NormalizeRegistryURL(invalid); err == nil {
			t.Errorf("expected %q to be rejected", invalid)
		}
	}
}

func hasDependencyRule(findings []skil.Finding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}

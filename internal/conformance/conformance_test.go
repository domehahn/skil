package conformance

import (
	"testing"

	"github.com/domehahn/skil/compat/asps"
)

func testRegistry() asps.Registry {
	return asps.Registry{
		Snapshot: "2026-01-01",
		Properties: []asps.Property{
			{ID: "ASP-04.01", DomainID: "ASP-04", Domain: "Identity", SKILStatus: "IMPLEMENTED"},
			{ID: "ASP-04.02", DomainID: "ASP-04", Domain: "Identity", SKILStatus: "PARTIAL"},
			{ID: "ASP-04.03", DomainID: "ASP-04", Domain: "Identity", SKILStatus: "NEW"},
			{ID: "ASP-04.04", DomainID: "ASP-04", Domain: "Identity", SKILStatus: "PROVIDER_BACKED"},
			{ID: "ASP-10.01", DomainID: "ASP-10", Domain: "MCP", SKILStatus: "IMPLEMENTED"},
			{ID: "ASP-10.02", DomainID: "ASP-10", Domain: "MCP", SKILStatus: "NEW"},
		},
	}
}

func TestEvaluateScoresSingleDomainProfile(t *testing.T) {
	report, err := Evaluate(testRegistry(), "identity")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Domains) != 1 || report.Domains[0].DomainID != "ASP-04" {
		t.Fatalf("expected only the ASP-04 domain: %#v", report.Domains)
	}
	dr := report.Domains[0]
	if dr.Total != 4 || dr.Implemented != 1 || dr.Partial != 1 || dr.Missing != 1 || dr.ProviderBacked != 1 {
		t.Fatalf("unexpected domain tally: %#v", dr)
	}
	// weight = 1 (implemented) + 0.5 (partial) + 0 (new) + 1 (provider_backed) = 2.5 / 4 = 0.625
	if report.Score < 0.624 || report.Score > 0.626 {
		t.Fatalf("expected a score of ~0.625, got %v", report.Score)
	}
}

func TestEvaluateCoreProfileCoversEveryDomain(t *testing.T) {
	report, err := Evaluate(testRegistry(), "core")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Domains) != 2 {
		t.Fatalf("expected both domains in the core profile: %#v", report.Domains)
	}
	if report.TotalProperties != 6 {
		t.Fatalf("expected all 6 properties counted, got %d", report.TotalProperties)
	}
}

func TestEvaluateUnknownProfileFails(t *testing.T) {
	if _, err := Evaluate(testRegistry(), "does-not-exist"); err == nil {
		t.Fatal("expected an unknown profile to return an error")
	}
}

func TestEvaluateMCPProfileScope(t *testing.T) {
	report, err := Evaluate(testRegistry(), "mcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Domains) != 1 || report.Domains[0].DomainID != "ASP-10" {
		t.Fatalf("expected only the ASP-10 domain: %#v", report.Domains)
	}
	if report.Score != 0.5 {
		t.Fatalf("expected a 50%% score (1 implemented, 1 new), got %v", report.Score)
	}
}

func TestProfileNamesAreSorted(t *testing.T) {
	names := ProfileNames()
	for i := 1; i < len(names); i++ {
		if names[i] <= names[i-1] {
			t.Fatalf("profile names not sorted: %v", names)
		}
	}
	if len(names) != len(Profiles) {
		t.Fatalf("expected %d names, got %d", len(Profiles), len(names))
	}
}

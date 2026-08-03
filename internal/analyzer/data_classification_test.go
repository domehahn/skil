package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func dataClassificationFindings(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewDataClassification().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestPurposeLimitationViolationIsDetected(t *testing.T) {
	content := `data_flows:
  - label: credential
    purpose: authentication
    sink_purpose: telemetry
`
	findings := dataClassificationFindings(t, "flows.yaml", content)
	if !hasRule(findings, "SKIL-DATA-PURPOSE-VIOLATION") {
		t.Fatalf("expected a purpose limitation violation to be detected: %#v", findings)
	}
}

func TestMatchingPurposeIsSafe(t *testing.T) {
	content := `data_flows:
  - label: credential
    purpose: authentication
    sink_purpose: authentication
`
	findings := dataClassificationFindings(t, "flows.yaml", content)
	if hasRule(findings, "SKIL-DATA-PURPOSE-VIOLATION") {
		t.Fatalf("a matching sink purpose should not fire: %#v", findings)
	}
}

func TestNonSensitiveLabelPurposeMismatchIsSafe(t *testing.T) {
	content := `data_flows:
  - label: public
    purpose: analytics
    sink_purpose: telemetry
`
	findings := dataClassificationFindings(t, "flows.yaml", content)
	if hasRule(findings, "SKIL-DATA-PURPOSE-VIOLATION") {
		t.Fatalf("a non-sensitive label should not trigger purpose limitation: %#v", findings)
	}
}

func TestUnboundedRetentionOfSensitiveDataIsDetected(t *testing.T) {
	content := `data_flows:
  - label: pii
    purpose: support
    retention: indefinite
`
	findings := dataClassificationFindings(t, "flows.yaml", content)
	if !hasRule(findings, "SKIL-DATA-RETENTION-UNBOUNDED") {
		t.Fatalf("expected unbounded retention of PII to be detected: %#v", findings)
	}
}

func TestBoundedRetentionIsSafe(t *testing.T) {
	content := `data_flows:
  - label: pii
    purpose: support
    retention: 30d
`
	findings := dataClassificationFindings(t, "flows.yaml", content)
	if hasRule(findings, "SKIL-DATA-RETENTION-UNBOUNDED") {
		t.Fatalf("a bounded retention period should not fire: %#v", findings)
	}
}

func TestOverbroadFieldCollectionOfSensitiveDataIsDetected(t *testing.T) {
	content := `data_flows:
  - label: financial
    purpose: billing
    fields: "*"
`
	findings := dataClassificationFindings(t, "flows.yaml", content)
	if !hasRule(findings, "SKIL-DATA-OVERBROAD-COLLECTION") {
		t.Fatalf("expected an unconstrained field collection to be detected: %#v", findings)
	}
}

func TestNarrowFieldCollectionIsSafe(t *testing.T) {
	content := `data_flows:
  - label: financial
    purpose: billing
    fields: ["invoice_id", "amount"]
`
	findings := dataClassificationFindings(t, "flows.yaml", content)
	if hasRule(findings, "SKIL-DATA-OVERBROAD-COLLECTION") {
		t.Fatalf("an explicit narrow field list should not fire: %#v", findings)
	}
}

package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func sample() skil.ScanResult {
	return skil.ScanResult{Artifact: skil.Artifact{Name: "x", Digest: "abc"}, Status: skil.StatusFail,
		RiskScore: 20, Findings: []skil.Finding{{RuleID: "R1", Title: "Issue", Message: "Issue",
			Description: "Description", Severity: skil.SeverityHigh, Location: skil.Location{File: "SKILL.md", StartLine: 2},
			Fingerprint: "fp"}}, Coverage: map[string]skil.CoverageState{"pattern": skil.CoverageCompleted}}
}

func TestAllReportFormats(t *testing.T) {
	for _, format := range []string{"terminal", "json", "markdown", "sarif"} {
		var out bytes.Buffer
		if err := Write(&out, format, sample()); err != nil || out.Len() == 0 {
			t.Fatalf("%s: %v", format, err)
		}
		if format == "sarif" {
			var doc SarifLog
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Version != "2.1.0" {
				t.Fatalf("invalid SARIF: %v", err)
			}
			if doc.Runs[0].Properties["skil"] == nil {
				t.Fatal("SARIF must bind the scanned artifact digest")
			}
		}
	}
}

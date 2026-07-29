package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func sample() skil.ScanResult {
	return skil.ScanResult{Artifact: skil.Artifact{Name: "x", Digest: "abc"}, Status: skil.StatusFail,
		RiskScore: 20, Findings: []skil.Finding{{RuleID: "R1", Title: "Issue", Message: "Issue",
			Description: "Description", Severity: skil.SeverityHigh, Location: skil.Location{File: "SKILL.md", StartLine: 2},
			Fingerprint: "fp", Remediation: "Fix the issue."}}, Coverage: map[string]skil.CoverageState{"pattern": skil.CoverageCompleted}}
}

func TestHumanReportsNeutralizeControlAndMarkdownInjection(t *testing.T) {
	result := sample()
	result.Artifact.Name = "safe\x1b[31m\nforged"
	result.Findings[0].Title = "bad|title`"
	result.Findings[0].Location.File = "x\u202ey"
	for _, format := range []string{"terminal", "markdown", "sarif"} {
		var out bytes.Buffer
		if err := Write(&out, format, result); err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(out.String(), "\x1b\u202e") || strings.Contains(out.String(), "\nforged") {
			t.Fatalf("%s retained report-control injection: %q", format, out.String())
		}
	}
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

func TestRichTerminalReportHasStableSectionsOrderingAndBounds(t *testing.T) {
	result := sample()
	result.Artifact.Source = "/tmp/example"
	result.Artifact.Files = []skil.File{
		{Path: "z.py", Data: []byte("print('z')\n")},
		{Path: "SKILL.md", Data: []byte("# example\n")},
	}
	result.Findings = []skil.Finding{
		{RuleID: "LOW", Title: "Low", Description: strings.Repeat("word ", 80), Severity: skil.SeverityLow,
			Location: skil.Location{File: "z.py", StartLine: 8}, Fingerprint: "b"},
		{RuleID: "HIGH", Title: "High", Description: "important", Severity: skil.SeverityHigh,
			Location: skil.Location{File: "SKILL.md", StartLine: 2}, Fingerprint: "a",
			Evidence: map[string]any{"payload": "safe\x1b[31m\u202evalue"}},
	}
	result.Coverage = map[string]skil.CoverageState{
		"pattern": skil.CoverageCompleted, "semantic": skil.CoverageNotRequested,
	}
	result.Diagnostics = []skil.Diagnostic{{Component: "provider", Level: "warning", Message: "not configured"}}
	result.Inspection = []skil.InspectionWorkItem{
		{Analyzer: "builtin.pattern", Outcome: skil.InspectionCompleted},
	}
	var out bytes.Buffer
	if err := Write(&out, "terminal", result); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, section := range []string{"ARTIFACT", "RISK ASSESSMENT", "COMPONENTS", "FINDINGS (2)", "INSPECTION COMPLETENESS", "ANALYZER STATUS", "COVERAGE", "LIMITATIONS & DIAGNOSTICS"} {
		if !strings.Contains(text, section) {
			t.Fatalf("missing section %q:\n%s", section, text)
		}
	}
	if strings.Index(text, "[high] HIGH") > strings.Index(text, "[low] LOW") {
		t.Fatalf("findings are not severity ordered:\n%s", text)
	}
	if strings.ContainsAny(text, "\x1b\u202e") {
		t.Fatalf("terminal controls survived:\n%q", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if len([]rune(line)) > terminalWidth {
			t.Fatalf("line exceeds %d columns (%d): %q", terminalWidth, len([]rune(line)), line)
		}
	}
}

func TestCompactAndMarkdownReportsRemainAvailable(t *testing.T) {
	var compact bytes.Buffer
	if err := WriteCompact(&compact, sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compact.String(), "- HIGH R1: Issue") {
		t.Fatalf("compact report changed unexpectedly: %s", compact.String())
	}
	var markdown bytes.Buffer
	if err := Write(&markdown, "markdown", sample()); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"## Risk assessment", "## Components", "## Findings", "## Inspection completeness", "## Analysis coverage", "## Limitations and diagnostics", "Remediation"} {
		if !strings.Contains(markdown.String(), section) {
			t.Fatalf("markdown report missing %q: %s", section, markdown.String())
		}
	}
}

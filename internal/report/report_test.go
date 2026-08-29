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
	for _, format := range []string{"terminal", "json", "markdown", "sarif", "html", "interactive-html"} {
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

func TestTerminalReportSurfacesTranscodedEncoding(t *testing.T) {
	result := sample()
	result.Artifact.Files = []skil.File{
		{Path: "SKILL.md", Encoding: "utf-16le"},
		{Path: "README.md", Encoding: "utf-8"},
		{Path: "logo.png", Encoding: "binary"},
	}
	var out bytes.Buffer
	if err := Write(&out, "terminal", result); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "ENCODING NOTES") {
		t.Fatalf("expected an ENCODING NOTES section when a file was transcoded: %s", text)
	}
	if !strings.Contains(text, "SKILL.md") || !strings.Contains(text, "utf-16le") {
		t.Fatalf("expected the transcoded file and its encoding to be listed: %s", text)
	}
	// Plain UTF-8 and binary files are the overwhelming common case and
	// must not clutter every report with a redundant note.
	afterComponents := text[strings.Index(text, "COMPONENTS"):]
	notesIdx := strings.Index(afterComponents, "ENCODING NOTES")
	if strings.Count(afterComponents[:notesIdx], "README.md") > 1 || strings.Count(afterComponents[:notesIdx], "logo.png") > 1 {
		t.Fatalf("utf-8/binary files should only appear in the COMPONENTS table, not ENCODING NOTES: %s", text)
	}
}

func TestTerminalReportOmitsEncodingNotesWhenAllUTF8(t *testing.T) {
	result := sample()
	result.Artifact.Files = []skil.File{{Path: "SKILL.md", Encoding: "utf-8"}}
	var out bytes.Buffer
	if err := Write(&out, "terminal", result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "ENCODING NOTES") {
		t.Fatalf("did not expect an ENCODING NOTES section when nothing was transcoded: %s", out.String())
	}
}

func TestTerminalReportSurfacesAnalyzabilityAndListsOpaqueFiles(t *testing.T) {
	result := sample()
	result.Analyzable = skil.AnalyzabilitySummary{Files: 2, Full: 1, Opaque: 1, Coverage: 0.5}
	result.Analyzability = []skil.AnalyzabilityRecord{
		{Path: "SKILL.md", State: skil.AnalyzabilityFull},
		{Path: "tool.exe", State: skil.AnalyzabilityOpaque, BinaryKind: "Windows PE executable"},
	}
	var out bytes.Buffer
	if err := Write(&out, "terminal", result); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "ANALYZABILITY") || !strings.Contains(text, "Coverage      50.0%") {
		t.Fatalf("expected an ANALYZABILITY section with coverage: %s", text)
	}
	if !strings.Contains(text, "tool.exe") || !strings.Contains(text, "Windows PE executable") {
		t.Fatalf("expected the opaque file and its binary kind to be listed: %s", text)
	}
	if strings.Contains(text, "SKILL.md") && strings.Count(text, "SKILL.md") > 1 {
		// SKILL.md appears once in COMPONENTS; it must not also be listed
		// under the opaque-files detail since it is fully analyzable.
		t.Fatalf("fully-analyzable file should not appear in the opaque-files list: %s", text)
	}
}

func TestTerminalReportOmitsAnalyzabilitySectionWhenNoFiles(t *testing.T) {
	result := sample()
	result.Analyzable = skil.AnalyzabilitySummary{}
	result.Analyzability = nil
	var out bytes.Buffer
	if err := Write(&out, "terminal", result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "ANALYZABILITY") {
		t.Fatalf("did not expect an ANALYZABILITY section for an empty artifact: %s", out.String())
	}
}

func TestTerminalReportSurfacesExceededAnalysisBudget(t *testing.T) {
	result := sample()
	result.Budget = skil.AnalysisBudgetUsage{
		RawBytes: skil.BudgetDimension{Used: 100, Limit: 100},
		Findings: skil.BudgetDimension{Used: 20_000, Limit: 10_000},
		WallTime: skil.BudgetDimension{Used: 130_000, Limit: 120_000},
		Exceeded: []string{"findings", "wall_time"},
	}
	var out bytes.Buffer
	if err := Write(&out, "terminal", result); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "ANALYSIS BUDGET") || !strings.Contains(text, "Exceeded: findings, wall_time") {
		t.Fatalf("expected an ANALYSIS BUDGET section listing the exceeded dimensions: %s", text)
	}
}

func TestTerminalReportOmitsAnalysisBudgetSectionWhenWithinBudget(t *testing.T) {
	result := sample()
	result.Budget = skil.AnalysisBudgetUsage{RawBytes: skil.BudgetDimension{Used: 10, Limit: 100}}
	var out bytes.Buffer
	if err := Write(&out, "terminal", result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "ANALYSIS BUDGET") {
		t.Fatalf("did not expect an ANALYSIS BUDGET section when nothing was exceeded: %s", out.String())
	}
}

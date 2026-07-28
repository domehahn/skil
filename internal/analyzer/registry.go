package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type Registry struct {
	analyzers []skil.Analyzer
}

func DefaultRegistry(vuln skil.VulnerabilityProvider) *Registry {
	items := []skil.Analyzer{
		NewPattern(), NewPythonAST(), NewStructuredAST(), NewTaint(), NewDependency(vuln), NewMCP(), NewUnicode(),
	}
	return &Registry{analyzers: items}
}

func (r *Registry) Register(a skil.Analyzer) error {
	meta := a.Metadata()
	if meta.ID == "" || meta.Version == "" {
		return fmt.Errorf("analyzer id and version are required")
	}
	for _, existing := range r.analyzers {
		if existing.Metadata().ID == meta.ID {
			return fmt.Errorf("analyzer %q already registered", meta.ID)
		}
	}
	r.analyzers = append(r.analyzers, a)
	return nil
}

func (r *Registry) Metadata() []skil.AnalyzerMetadata {
	out := make([]skil.AnalyzerMetadata, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		out = append(out, a.Metadata())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *Registry) Scan(ctx context.Context, ac skil.AnalysisContext) (skil.ScanResult, error) {
	nativeRules := nativeRuleIDs()
	result := skil.ScanResult{
		SchemaVersion: "1.0.0", Artifact: ac.Artifact, Findings: []skil.Finding{},
		Coverage: map[string]skil.CoverageState{
			"pattern": skil.CoverageNotRequested, "ast": skil.CoverageNotRequested,
			"static-code": skil.CoverageNotRequested,
			"taint":       skil.CoverageNotRequested, "dependency": skil.CoverageNotRequested,
			"vulnerability": skil.CoverageNotRequested,
			"mcp":           skil.CoverageNotRequested, "malware": skil.CoverageNotAvailable,
			"semantic": skil.CoverageNotRequested, "behavioral": skil.CoverageNotRun,
		},
		Scanners: []string{"skil"},
	}
	for _, a := range r.analyzers {
		meta := a.Metadata()
		findings, err := a.Analyze(ctx, ac)
		if err != nil {
			return result, fmt.Errorf("%s analyzer: %w", meta.ID, err)
		}
		for _, finding := range findings {
			if strings.HasPrefix(finding.RuleID, "SKIL-") && !nativeRuleKnown(nativeRules, finding.RuleID) {
				return result, fmt.Errorf("%s analyzer emitted unpublished native rule %q", meta.ID, finding.RuleID)
			}
		}
		result.Findings = append(result.Findings, findings...)
		for _, typ := range meta.AnalysisTypes {
			result.Coverage[typ] = skil.CoverageCompleted
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
	result.Maximum, result.RiskScore, result.Status = Risk(result.Findings, result.Coverage)
	result.Verdict = Verdict(result.Maximum, result.RiskScore, result.Coverage)
	return result, nil
}

func nativeRuleIDs() []string {
	builtin := BuiltinRules()
	out := make([]string, 0, len(builtin))
	for _, rule := range builtin {
		out = append(out, rule.ID)
	}
	return out
}

func nativeRuleKnown(rules []string, id string) bool {
	for _, rule := range rules {
		if rule == id || strings.HasSuffix(rule, "*") && strings.HasPrefix(id, strings.TrimSuffix(rule, "*")) {
			return true
		}
	}
	return false
}

// Verdict is skil's native disposition. It deliberately uses boundaries that
// follow the local threat model rather than a third-party score table.
func Verdict(maximum skil.Severity, score int, coverage map[string]skil.CoverageState) skil.Verdict {
	if maximum == skil.SeverityCritical || maximum == skil.SeverityHigh || score >= 40 {
		return skil.VerdictBlock
	}
	if maximum == skil.SeverityMedium || score >= 10 ||
		coverage["ast"] != skil.CoverageCompleted || coverage["taint"] != skil.CoverageCompleted {
		return skil.VerdictReview
	}
	return skil.VerdictClear
}

func Risk(findings []skil.Finding, coverage map[string]skil.CoverageState) (skil.Severity, int, skil.Status) {
	weights := map[skil.Severity]int{
		skil.SeverityInfo: 0, skil.SeverityLow: 3, skil.SeverityMedium: 8,
		skil.SeverityHigh: 18, skil.SeverityCritical: 30,
	}
	ranks := map[skil.Severity]int{
		skil.SeverityInfo: 0, skil.SeverityLow: 1, skil.SeverityMedium: 2,
		skil.SeverityHigh: 3, skil.SeverityCritical: 4,
	}
	max := skil.SeverityInfo
	score := 0.0
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		score += float64(weights[f.Severity]) * f.Confidence
		if f.Category == "contract-conformance" {
			score += 10
		}
		if ranks[f.Severity] > ranks[max] {
			max = f.Severity
		}
	}
	if coverage["ast"] != skil.CoverageCompleted || coverage["taint"] != skil.CoverageCompleted {
		score += 5
	}
	if score > 100 {
		score = 100
	}
	status := skil.StatusPass
	if max == skil.SeverityMedium {
		status = skil.StatusWarn
	} else if ranks[max] >= ranks[skil.SeverityHigh] {
		status = skil.StatusFail
	}
	return max, int(score + 0.5), status
}

func makeFinding(rule RulePattern, file skil.File, line int, matched string) skil.Finding {
	fp := fingerprint(rule.Rule.ID, file.Path, strconv.Itoa(line), normalizeEvidence(matched))
	return skil.Finding{
		ID: "F-" + strings.ToUpper(fp[:12]), RuleID: rule.Rule.ID, Category: rule.Rule.Category,
		Severity: rule.Rule.Severity, Confidence: rule.Confidence, Title: rule.Rule.Title,
		Message: rule.Rule.Description, Description: rule.Rule.Description,
		Location: skil.Location{File: file.Path, StartLine: line, EndLine: line},
		Evidence: map[string]any{"match": truncate(matched, 160)}, Remediation: rule.Rule.Remediation,
		References: rule.Rule.References, Fingerprint: fp,
	}
}

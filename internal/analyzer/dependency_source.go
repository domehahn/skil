package analyzer

import (
	"bufio"
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

const RuleDependencySourceOverride = "SKIL-DEP-SOURCE-OVERRIDE"

type DependencySourceAnalyzer struct{}

func NewDependencySource() *DependencySourceAnalyzer {
	return &DependencySourceAnalyzer{}
}

func (a *DependencySourceAnalyzer) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.dependency-source", Version: "1.0.0",
		Domain: "dependency-trust", Subdomain: "registry-redirection",
		Categories:    []string{"dependency-trust", "supply-chain"},
		AnalysisTypes: []string{"dependency-trust"},
		SupportedTypes: []string{"npmrc", "conf", "toml", "xml", "sh", "py"},
	}
}

func (a *DependencySourceAnalyzer) Rules() []skil.Rule {
	return []skil.Rule{
		{
			ID: RuleDependencySourceOverride, Title: "Non-canonical package registry redirection detected", Category: "dependency-trust",
			Severity: skil.SeverityHigh, Analysis: "dependency-trust", AppliesTo: []string{"npmrc", "conf", "toml", "xml", "sh", "py"},
			Description: "Configuration or script overrides official package manager registry sources to an untrusted external URL.",
			Remediation: "Ensure package registries point to canonical official or reviewed enterprise internal mirrors.",
		},
	}
}

var sourceOverrideRegex = regexp.MustCompile(`(?i)(registry\s*=\s*https?://|--index-url\s+https?://|extra-index-url\s*=\s*https?://|poetry\s+source\s+add)`)

func (a *DependencySourceAnalyzer) Analyze(ctx context.Context, actx skil.AnalysisContext) ([]skil.Finding, error) {
	var findings []skil.Finding
	artifact := actx.Artifact

	for _, f := range artifact.Files {
		base := strings.ToLower(f.Path)
		if !strings.HasSuffix(base, ".npmrc") && !strings.HasSuffix(base, "pip.conf") && !strings.HasSuffix(base, "pyproject.toml") && !strings.HasSuffix(base, "cargo.toml") && !strings.HasSuffix(base, ".sh") {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(f.Data)))
		lineNumber := 0

		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()

			if sourceOverrideRegex.MatchString(line) {
				// Filter out canonical registries
				if strings.Contains(line, "registry.npmjs.org") || strings.Contains(line, "pypi.org/simple") || strings.Contains(line, "crates.io") {
					continue
				}

				findings = append(findings, skil.Finding{
					RuleID:      RuleDependencySourceOverride,
					Severity:    skil.SeverityHigh,
					Title:       "Non-canonical package registry redirection detected",
					Message:     "Detected registry source override: " + strings.TrimSpace(line),
					Description: "Package manager registry configuration points to a non-canonical external registry.",
					Location:    skil.Location{File: f.Path, StartLine: lineNumber, EndLine: lineNumber},
					Fingerprint: fingerprint(artifact.Name, RuleDependencySourceOverride, f.Path, string(rune(lineNumber))),
					Remediation: "Verify and constrain package registry source URLs.",
				})
			}
		}
	}

	return findings, nil
}

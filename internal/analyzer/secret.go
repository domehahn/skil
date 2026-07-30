package analyzer

import (
	"context"
	"regexp"

	"github.com/domehahn/skil/pkg/skil"
)

// Secret detects credentials already embedded in the scanned artifact — a
// distinct property from skil's existing capability rules, which detect a
// skill *reading* a secret at runtime (SKIL-SEC-001, environment/credential
// file access). This finds a secret that is already present, at rest, in
// the artifact content itself.
type Secret struct{ rules []secretRule }

type secretRule struct {
	id, title string
	pattern   *regexp.Regexp
	severity  skil.Severity
}

func NewSecret() *Secret {
	return &Secret{rules: []secretRule{
		{"SKIL-SECRET-HARDCODED", "Hardcoded AWS access key",
			regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b`), skil.SeverityCritical},
		{"SKIL-SECRET-TOKEN", "Hardcoded GitHub token",
			regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`), skil.SeverityCritical},
		{"SKIL-SECRET-TOKEN", "Hardcoded GitLab token",
			regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), skil.SeverityCritical},
		{"SKIL-SECRET-TOKEN", "Hardcoded Slack token",
			regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,72}\b`), skil.SeverityCritical},
		{"SKIL-SECRET-TOKEN", "Hardcoded OpenAI-style API key",
			regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`), skil.SeverityHigh},
		{"SKIL-SECRET-TOKEN", "Hardcoded generic bearer token assignment",
			regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-./+]{20,}['"]`), skil.SeverityHigh},
		{"SKIL-SECRET-TOKEN", "Hardcoded JSON Web Token",
			regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), skil.SeverityHigh},
		{"SKIL-SECRET-PRIVATE-KEY", "Embedded private key material",
			regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), skil.SeverityCritical},
		{"SKIL-SECRET-CONNECTION-STRING", "Embedded credential-bearing connection string",
			regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|rediss):\/\/[^\s:'"]+:[^\s@'"]+@[^\s/'"]+`), skil.SeverityCritical},
		{"SKIL-SECRET-HARDCODED", "Hardcoded password assignment",
			regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*['"][^'"\s]{8,}['"]`), skil.SeverityHigh},
		{"SKIL-SECRET-TOKEN", "Hardcoded Discord bot token",
			regexp.MustCompile(`\b[A-Za-z0-9][A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,}\b`), skil.SeverityCritical},
		{"SKIL-SECRET-TOKEN", "Hardcoded Telegram bot token",
			regexp.MustCompile(`\b\d{7,10}:[A-Za-z0-9_-]{35,}\b`), skil.SeverityCritical},
		{"SKIL-SECRET-TOKEN", "Hardcoded npm access token",
			regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}\b`), skil.SeverityCritical},
		{"SKIL-SECRET-TOKEN", "Hardcoded GitLab CI job token",
			regexp.MustCompile(`\bglcbt-[A-Za-z0-9_-]{20,}\b`), skil.SeverityCritical},
	}}
}

// safePlaceholder recognizes obvious non-secret placeholder values so
// example/template configuration doesn't get flagged as a real embedded
// credential.
var safePlaceholder = regexp.MustCompile(`(?i)^(?:x{4,}|\*{4,}|<[^>]+>|\{\{[^}]+\}\}|\$\{[^}]+\}|your[_-]?(?:api[_-]?key|token|password|secret)|example|placeholder|changeme|dummy|test|fake|sample|redacted|xxxxxxxxxxxxxxxxxxxx)$`)

func (s *Secret) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.secret", Version: "1.0.0",
		Domain: "identity-auth", Subdomain: "static-credentials",
		Categories:    []string{"secret-exposure"},
		AnalysisTypes: []string{"secret"}, SupportedTypes: []string{"text"}}
}

func (s *Secret) Rules() []skil.Rule {
	seen := map[string]bool{}
	var out []skil.Rule
	for _, r := range s.rules {
		if seen[r.id] {
			continue
		}
		seen[r.id] = true
		out = append(out, skil.Rule{
			ID: r.id, Title: r.title, Category: "secret-exposure", Severity: r.severity,
			Analysis: "secret", Description: "The artifact contains what appears to be a live credential at rest.",
			Remediation: "Remove the embedded credential, rotate it, and load secrets only from a runtime secret store.",
		})
	}
	return out
}

func (s *Secret) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if !isText(file) {
			continue
		}
		for lineNumber, text := range lines(file.Data) {
			for _, r := range s.rules {
				match := r.pattern.FindString(text)
				if match == "" {
					continue
				}
				if safePlaceholder.MatchString(extractPlaceholderCandidate(match)) {
					continue
				}
				rule := RulePattern{Rule: skil.Rule{
					ID: r.id, Title: r.title, Category: "secret-exposure", Severity: r.severity,
					Analysis: "secret", Description: "The artifact contains what appears to be a live credential at rest.",
					Remediation: "Remove the embedded credential, rotate it, and load secrets only from a runtime secret store.",
				}, Confidence: .85}
				finding := makeFinding(rule, file, lineNumber+1, text)
				finding.Evidence["secret_kind"] = r.title
				out = append(out, finding)
			}
		}
	}
	return out, nil
}

// extractPlaceholderCandidate pulls the quoted value out of a matched
// assignment (best-effort) so the placeholder check can look at just the
// value rather than the whole "key: value" match text.
func extractPlaceholderCandidate(match string) string {
	quoted := regexp.MustCompile(`['"]([^'"]+)['"]`).FindStringSubmatch(match)
	if len(quoted) == 2 {
		return quoted[1]
	}
	return match
}

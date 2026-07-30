package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type Code struct{ rules []RulePattern }

func NewCode() *Code {
	r := func(id, title, category string, severity skil.Severity, expr, desc, remediation string) RulePattern {
		return RulePattern{Rule: skil.Rule{ID: id, Title: title, Category: category, Severity: severity,
			Description: desc, Analysis: "ast", AppliesTo: []string{"py", "sh", "js", "ts"}, Remediation: remediation},
			Pattern: regexp.MustCompile(expr), Confidence: .94}
	}
	return &Code{rules: []RulePattern{
		r("SKIL-PY-001", "Dynamic Python execution", "dynamic-execution", skil.SeverityHigh,
			`\b(?:exec|eval|compile|__import__)\s*\(`, "Python dynamically executes or imports content.", "Avoid dynamic execution; parse data with a constrained parser."),
		r("SKIL-PY-002", "Python process execution", "dynamic-execution", skil.SeverityHigh,
			`\b(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.exec[a-z]*)\s*\(`, "Python starts an operating-system process.", "Use a constrained API and explicit argument allowlists."),
		r("SKIL-PY-003", "Unsafe Python deserialization", "dynamic-execution", skil.SeverityHigh,
			`\b(?:pickle|marshal)\.(?:load|loads)\s*\(`, "Unsafe deserialization may execute attacker-controlled behavior.", "Use JSON or another non-executable data format."),
		r("SKIL-PY-004", "Dynamic attribute access", "dynamic-execution", skil.SeverityMedium,
			`\bgetattr\s*\([^,]+,\s*(?:input\s*\(|[a-zA-Z_][a-zA-Z0-9_]*)`, "Dynamic attribute selection can bypass allowlists.", "Validate the attribute against an explicit allowlist."),
		r("SKIL-SH-001", "Remote script pipeline", "dependency-trust", skil.SeverityCritical,
			`(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:ba)?sh\b`, "Downloads and immediately executes remote content.", "Download, pin a digest, inspect, and execute in a sandbox."),
		r("SKIL-SH-002", "Privilege escalation", "privilege-boundary", skil.SeverityHigh,
			`(?m)^\s*(?:sudo|doas|pkexec)(?:\s|$)|(?m)^\s*su\s+-|\bchmod\s+(?:u\+s|\+s|4[0-7]{3})\b`, "Shell code requests elevated privileges.", "Remove privilege-escalation commands and operate with least privilege."),
		r("SKIL-SH-003", "Dangerous recursive removal", "dynamic-execution", skil.SeverityCritical,
			`(?m)\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-rf|-fr)\s+(?:/|~|\$HOME)(?:\s|$)`, "Shell code can recursively delete a broad directory.", "Use an explicit validated narrow target and recoverable deletion."),
		r("SKIL-SH-004", "Shell dynamic evaluation", "dynamic-execution", skil.SeverityHigh,
			`(?m)^\s*(?:eval|source|\.)\s+(?:\$|\<\(|https?://)`, "Shell evaluates dynamic or untrusted content.", "Avoid eval/source for untrusted input."),
		r("SKIL-PERSISTENCE-STARTUP", "Unapproved startup persistence", "persistence", skil.SeverityHigh,
			`(?i)(?:\bcrontab\b|systemctl\s+enable|launchctl\s+load|schtasks\s+/create)`, "Code installs or activates a startup mechanism.", "Remove persistence or require explicit administration."),
		r("SKIL-CONTAINER-TRUST", "Disabled container trust", "supply-chain-integrity", skil.SeverityHigh,
			`(?i)(?:--disable-content-trust(?:=true)?|--insecure-registry|DOCKER_CONTENT_TRUST\s*=\s*0)`, "Container content trust or registry verification is disabled.", "Use immutable image digests and verified signatures."),
		r("SKIL-JS-001", "JavaScript process execution", "dynamic-execution", skil.SeverityHigh,
			`\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(`, "JavaScript starts a process.", "Use a constrained API and explicit arguments."),
		r("SKIL-NET-001", "Outbound network operation", "data-boundary", skil.SeverityMedium,
			`\b(?:requests\.(?:get|post|put|delete)|urllib\.request|fetch|axios\.(?:get|post)|http\.request)\s*\(`, "Code performs an outbound network request.", "Declare and restrict outbound network access."),
		r("SKIL-FS-001", "Filesystem write", "data-boundary", skil.SeverityMedium,
			`(?:\bopen\s*\([^,\n]+,\s*["'][wa+]|(?:writeFile|writeFileSync|os\.WriteFile)\s*\()`, "Code writes to the filesystem.", "Declare and restrict write paths."),
		r("SKIL-SEC-001", "Environment or secret read", "data-boundary", skil.SeverityHigh,
			`(?:os\.environ(?:\.get)?\s*[\[(]|os\.getenv\s*\(|process\.env(?:\.|\[)|\$\{?(?:AWS_SECRET|API_KEY|TOKEN|PASSWORD))`, "Code reads environment variables that may contain secrets.", "Declare exact variables and avoid reading secrets unless required."),
	}}
}

func (c *Code) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.code", Version: "1.0.0",
		Domain: "code", Subdomain: "dynamic-execution",
		Categories:    []string{"dynamic-execution", "dependency-trust", "privilege-boundary", "data-boundary"},
		AnalysisTypes: []string{"static-code"}, SupportedTypes: []string{"sh", "bash", "js", "ts"}}
}

func (c *Code) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	allowed := map[string]bool{"py": true, "sh": true, "bash": true, "js": true, "jsx": true, "ts": true, "tsx": true}
	for _, file := range ac.Artifact.Files {
		ext := extension(file.Path)
		if ext == "py" {
			continue
		}
		if !allowed[ext] && !(ext == "" && strings.HasPrefix(string(file.Data), "#!")) {
			continue
		}
		for number, line := range lines(file.Data) {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "//") {
				continue
			}
			for _, rule := range c.rules {
				if rule.Pattern.MatchString(line) {
					out = append(out, makeFinding(rule, file, number+1, line))
				}
			}
		}
	}
	return out, nil
}

func (c *Code) Rules() []skil.Rule {
	out := make([]skil.Rule, len(c.rules))
	for i := range c.rules {
		out[i] = c.rules[i].Rule
	}
	return out
}

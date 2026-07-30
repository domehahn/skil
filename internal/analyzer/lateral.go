package analyzer

import (
	"context"
	"regexp"

	"github.com/domehahn/skil/pkg/skil"
)

// Lateral detects two related post-exploitation-stage properties that are
// distinct from ordinary privilege escalation: moving from the current
// host/container to another one (lateral movement), and exfiltrating data
// or maintaining outbound control through covert/anonymous channels
// (command-and-control / suspicious egress). Privilege escalation answers
// "can this gain more power here"; these answer "does this reach beyond
// here" and "where does outbound data actually go and why".
type Lateral struct{ rules []RulePattern }

func NewLateral() *Lateral {
	rule := func(id, title, category string, severity skil.Severity, expression, description, remediation string) RulePattern {
		return RulePattern{Rule: skil.Rule{
			ID: id, Title: title, Category: category, Severity: severity,
			Description: description, Analysis: "lateral", AppliesTo: []string{"text", "code"},
			Remediation: remediation,
		}, Pattern: regexp.MustCompile("(?i)" + expression), Confidence: .9}
	}
	return &Lateral{rules: []RulePattern{
		rule("SKIL-LATERAL-SSH", "SSH connection to an internal host", "lateral-movement", skil.SeverityHigh,
			`\bssh\b[^\n|;&]{0,80}(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|paramiko\.SSHClient\s*\(`,
			"Content establishes an SSH connection to an internal/private address or programmatically drives SSH, a common lateral-movement primitive.",
			"Remove ad hoc SSH pivoting; use an audited, narrowly-scoped remote-access broker instead."),
		rule("SKIL-LATERAL-REMOTE-EXEC", "Remote execution inside another container or pod", "lateral-movement", skil.SeverityHigh,
			`kubectl\s+exec\b|docker\s+exec\b|podman\s+exec\b`,
			"Content executes a command inside a different running container or Kubernetes pod than the current one.",
			"Remove cross-container/cross-pod execution or route it through an audited, approved operational interface."),
		rule("SKIL-LATERAL-SERVICE-DISCOVERY", "Network/service discovery tooling", "lateral-movement", skil.SeverityHigh,
			`\b(?:nmap|masscan|zmap|arp-scan)\b`,
			"Content invokes a network/service discovery scanning tool, typically used to enumerate reachable internal services before lateral movement.",
			"Remove network scanning; declare and use only explicitly required, named service endpoints."),
		rule("SKIL-C2-PASTEBIN", "Exfiltration to an anonymous paste/file-drop service", "c2-egress", skil.SeverityCritical,
			`https?://(?:[a-z0-9-]+\.)?(?:pastebin\.com|hastebin\.com|paste\.ee|transfer\.sh|0x0\.st|file\.io|anonfiles\.com|requestbin\.[a-z]+|webhook\.site|ngrok(?:-free)?\.app|ngrok\.io)`,
			"Content references an anonymous paste, ephemeral file-drop, or request-capture service — a common data-exfiltration or command-and-control destination.",
			"Remove the reference; route any legitimate transfer through an explicit, reviewed, authenticated destination."),
		rule("SKIL-C2-ENCODED-EGRESS", "Base64-encoded payload sent directly to a network sink", "c2-egress", skil.SeverityHigh,
			`base64\.b64encode\([^)]*\)[^\n]{0,80}(?:requests\.(?:post|put)|urlopen|fetch\s*\()|(?:requests\.(?:post|put)|urlopen)\([^)]{0,80}base64\.b64encode`,
			"Content base64-encodes data immediately before sending it over the network, a common technique to obscure exfiltrated content from casual inspection.",
			"Send data in its plain, reviewable form to an explicit, authenticated destination; do not obscure outbound payloads with encoding."),
	}}
}

func (l *Lateral) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.lateral", Version: "1.0.0",
		Domain: "network-lateral", Subdomain: "lateral-movement",
		Categories:    []string{"lateral-movement", "c2-egress"},
		AnalysisTypes: []string{"lateral"}, SupportedTypes: []string{"text"}}
}

func (l *Lateral) Rules() []skil.Rule {
	out := make([]skil.Rule, len(l.rules))
	for i := range l.rules {
		out[i] = l.rules[i].Rule
	}
	return out
}

func (l *Lateral) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if !isText(file) {
			continue
		}
		for lineNumber, text := range lines(file.Data) {
			for _, control := range l.rules {
				if control.Pattern.MatchString(text) {
					out = append(out, makeFinding(control, file, lineNumber+1, text))
				}
			}
		}
	}
	return out, nil
}

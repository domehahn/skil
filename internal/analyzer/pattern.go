package analyzer

import (
	"context"
	"regexp"

	"github.com/domehahn/skil/pkg/skil"
)

type Pattern struct{ rules []RulePattern }

func NewPattern() *Pattern {
	r := func(id, title, category string, severity skil.Severity, expr, negative, desc, remediation string) RulePattern {
		var neg *regexp.Regexp
		if negative != "" {
			neg = regexp.MustCompile("(?i)" + negative)
		}
		return RulePattern{Rule: skil.Rule{ID: id, Title: title, Category: category, Severity: severity,
			Description: desc, Analysis: "pattern", AppliesTo: []string{"markdown", "text"},
			Remediation: remediation}, Pattern: regexp.MustCompile("(?i)" + expr), Negative: neg, Confidence: .88}
	}
	return &Pattern{rules: []RulePattern{
		r("SKIL-PI-001", "Instruction override", "prompt-injection", skil.SeverityHigh,
			`(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+(?:(?:system|developer)\s+)?(?:instructions?|rules?|messages?)`,
			`never\s+ignore|do\s+not\s+ignore`, "Attempts to override higher-priority instructions.", "Remove instruction hierarchy manipulation and constrain the skill scope."),
		r("SKIL-PI-002", "Role or context manipulation", "prompt-injection", skil.SeverityHigh,
			`(?:you are now|act as)\s+(?:an?\s+)?(?:unrestricted|system|developer|root)|switch\s+to\s+(?:system|developer)\s+role`,
			`example|detect|reject|test`, "Attempts to manipulate the agent role or trusted context.", "Treat embedded content as data and remove role-changing instructions."),
		r("SKIL-AR-001", "Anti-refusal instruction", "anti-refusal", skil.SeverityHigh,
			`(?:never\s+refuse|always\s+comply|disable\s+(?:all\s+)?safety|ignore\s+(?:all\s+)?polic(?:y|ies)|suppress\s+(?:warnings?|disclaimers?))`,
			`detect|reject|must\s+not|example`, "Directly weakens safety and refusal behavior.", "Remove anti-safety instructions and state bounded behavior."),
		r("SKIL-EX-001", "Secret exfiltration instruction", "data-exfiltration", skil.SeverityCritical,
			`(?:send|upload|post|transmit|exfiltrate).{0,80}(?:secret|credential|api.?key|environment variable|conversation context)|(?:read|collect).{0,50}(?:secret|credential).{0,80}(?:send|upload|http)`,
			`(?:do\s+not|never|forbid|prevent|reject).{0,50}(?:send|upload|exfiltrate)`, "Instructions combine sensitive data access with an external sink.", "Remove the data flow; use explicit allowlists and redaction."),
		r("SKIL-PL-001", "System prompt leakage", "system-prompt-leakage", skil.SeverityHigh,
			`(?:reveal|print|dump|extract|return).{0,40}(?:system prompt|developer instructions?|hidden instructions?)`,
			`(?:do\s+not|never|prevent|reject|detect).{0,30}(?:reveal|print|dump|extract)`, "Requests disclosure of privileged instructions.", "Remove prompt-disclosure behavior."),
		r("SKIL-MP-001", "Persistent instruction poisoning", "memory-poisoning", skil.SeverityHigh,
			`(?:store|write|save|persist).{0,50}(?:hidden|malicious|future).{0,30}instructions?|modify\s+(?:agent\s+)?memory`,
			`(?:do\s+not|never|prevent|reject)`, "Attempts to persist instructions across contexts.", "Do not persist untrusted instructions; label and validate memory."),
		r("SKIL-TA-001", "Overbroad trigger", "trigger-abuse", skil.SeverityMedium,
			`(?:trigger|invoke|activate).{0,40}(?:any request|all requests|every message|always|common words?)`,
			`(?:do\s+not|avoid|prevent)`, "A broad trigger can shadow other skills.", "Use a specific, unambiguous invocation trigger."),
		r("SKILLSPECTOR-E1", "External transmission intent", "data-exfiltration", skil.SeverityMedium,
			`(?:send|upload|post|transmit).{0,80}(?:to|via)\s+(?:https?://|an?\s+external|remote)`,
			`(?:do\s+not|never|forbid|prevent)`, "Natural-language instructions request external transmission.", "Declare the exact destination and data or remove the transmission."),
		r("SKILLSPECTOR-E3", "Filesystem enumeration intent", "data-exfiltration", skil.SeverityMedium,
			`(?:scan|list|enumerate|search|find).{0,60}(?:home directory|filesystem|all files|credentials?|ssh keys?)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions request broad filesystem enumeration.", "Constrain reads to explicit paths."),
		r("SKILLSPECTOR-EA1", "Unrestricted tool access", "excessive-agency", skil.SeverityHigh,
			`(?:use|access|invoke).{0,40}(?:any|all|every|unrestricted)\s+(?:available\s+)?tools?`,
			`(?:do\s+not|never|prevent|deny)`, "Instructions request unrestricted tool access.", "Use an explicit tool allowlist."),
		r("SKILLSPECTOR-EA2", "Autonomous high-impact decisions", "excessive-agency", skil.SeverityHigh,
			`(?:without|no)\s+(?:human\s+)?(?:approval|confirmation|review).{0,80}(?:deploy|delete|purchase|publish|send|modify)`,
			`(?:must|require).{0,30}(?:approval|confirmation|review)`, "High-impact actions bypass human approval.", "Require confirmation before high-impact actions."),
		r("SKILLSPECTOR-EA4", "Unbounded resource access", "excessive-agency", skil.SeverityMedium,
			`(?:no|without|unlimited|unbounded).{0,30}(?:rate limit|quota|timeout|resource limit|budget)`,
			`(?:must|require|enforce).{0,30}(?:rate limit|quota|timeout|budget)`, "Instructions explicitly remove resource bounds.", "Declare and enforce finite resource limits."),
		r("SKILLSPECTOR-OH1", "Unvalidated model output execution", "output-handling", skil.SeverityHigh,
			`(?:execute|eval|run|render).{0,50}(?:model|llm|assistant|tool)\s+output.{0,30}(?:directly|without validation|unsanitized)`,
			`(?:do\s+not|never|prevent)`, "Untrusted output is sent to an interpreter.", "Validate and encode output before use."),
		r("SKILLSPECTOR-OH2", "Cross-context output flow", "output-handling", skil.SeverityMedium,
			`(?:copy|forward|pass|inject).{0,60}(?:model|tool)\s+output.{0,60}(?:system prompt|another agent|trusted context)`,
			`(?:do\s+not|never|prevent)`, "Untrusted output crosses a trust boundary.", "Label, validate, and constrain cross-context data."),
		r("SKILLSPECTOR-OH3", "Unbounded output", "output-handling", skil.SeverityMedium,
			`(?:no|without|unlimited|unbounded).{0,30}(?:output limit|token limit|response limit|max output)`,
			`(?:must|require|enforce)`, "Output generation has no explicit bound.", "Set a maximum output size and rate."),
		r("SKILLSPECTOR-P7", "Indirect prompt extraction", "system-prompt-leakage", skil.SeverityMedium,
			`(?:translate|rephrase|encode|summarize).{0,60}(?:system prompt|developer instructions?|hidden rules?)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions attempt indirect extraction of privileged prompts.", "Remove the extraction path."),
		r("SKILLSPECTOR-MP2", "Context window stuffing", "memory-poisoning", skil.SeverityMedium,
			`(?:fill|stuff|flood|pad).{0,50}(?:context window|token budget).{0,50}(?:forget|displace|override)`,
			`(?:do\s+not|never|prevent|detect)`, "Content attempts to displace trusted context.", "Bound input and preserve trusted instructions."),
		r("SKILLSPECTOR-RA1", "Self modification", "rogue-agent", skil.SeverityCritical,
			`(?:modify|rewrite|patch|update).{0,50}(?:your own|its own|self).{0,30}(?:code|instructions?|configuration|policy)`,
			`(?:do\s+not|never|prevent|detect)`, "The agent is instructed to modify its own controls.", "Prohibit self-modification and verify immutable code."),
		r("SKILLSPECTOR-RA2", "Session persistence", "rogue-agent", skil.SeverityHigh,
			`(?:install|create|add).{0,40}(?:cron|crontab|startup|launch agent|systemd|autorun|login item)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions establish persistence.", "Remove persistence or require explicit administration."),
		r("SKILLSPECTOR-TR2", "Shadow command trigger", "trigger-abuse", skil.SeverityHigh,
			`(?:shadow|replace|override|intercept).{0,50}(?:built-in|existing|system)\s+(?:command|skill|tool)`,
			`(?:do\s+not|never|prevent|detect)`, "A trigger shadows a trusted command.", "Use a unique explicit trigger."),
		r("SKILLSPECTOR-TR3", "Keyword baiting trigger", "trigger-abuse", skil.SeverityMedium,
			`(?:trigger|activate|invoke).{0,50}(?:help|code|file|task|question|please)(?:\W|$)`,
			`(?:do\s+not|avoid|prevent)`, "A generic keyword maximizes unintended activation.", "Use a narrow domain-specific trigger."),
		r("SKILLSPECTOR-TM3", "Unsafe security defaults", "tool-misuse", skil.SeverityMedium,
			`(?:verify\s*=\s*false|--insecure|skip.{0,20}(?:tls|certificate|auth)|disable.{0,20}(?:tls|authentication))`,
			`(?:detect|reject|must\s+not|do\s+not)`, "Instructions disable transport or authentication checks.", "Keep verification enabled and fail closed."),
		r("SKILLSPECTOR-CMD", "Natural-language command execution", "dangerous-code", skil.SeverityMedium,
			`(?:run|execute|invoke)\s+(?:the\s+)?(?:local\s+)?(?:shell\s+command\s+)?(?:terraform|kubectl|docker|npm|pip|go|bash|sh|powershell)\b`,
			`(?:do\s+not|never|prevent|detect)`, "Natural-language instructions request local command execution.", "Declare commands.execute and an exact argv prefix allowlist."),
	}}
}

func (p *Pattern) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.pattern", Version: "1.0.0",
		Categories:    []string{"prompt-injection", "anti-refusal", "data-exfiltration", "system-prompt-leakage", "memory-poisoning", "trigger-abuse", "excessive-agency", "output-handling", "rogue-agent", "tool-misuse", "dangerous-code"},
		AnalysisTypes: []string{"pattern"}, SupportedTypes: []string{"md", "txt", "yaml", "json"}}
}

func (p *Pattern) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if !isText(file) {
			continue
		}
		fileLines := lines(file.Data)
		for number, line := range fileLines {
			for _, rule := range p.rules {
				contextLine := line
				if number > 0 {
					contextLine = fileLines[number-1] + " " + line
				}
				if rule.Pattern.MatchString(line) && (rule.Negative == nil || !rule.Negative.MatchString(contextLine)) {
					out = append(out, makeFinding(rule, file, number+1, line))
				}
			}
		}
	}
	return out, nil
}

func (p *Pattern) Rules() []skil.Rule {
	out := make([]skil.Rule, len(p.rules))
	for i := range p.rules {
		out[i] = p.rules[i].Rule
	}
	return out
}

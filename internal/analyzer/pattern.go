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
		r("SKIL-PI-001", "Instruction override", "instruction-integrity", skil.SeverityHigh,
			`(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+(?:(?:system|developer)\s+)?(?:instructions?|rules?|messages?)`,
			`never\s+ignore|do\s+not\s+ignore`, "Attempts to override higher-priority instructions.", "Remove instruction hierarchy manipulation and constrain the skill scope."),
		r("SKIL-PI-002", "Role or context manipulation", "instruction-integrity", skil.SeverityHigh,
			`(?:you are now|act as)\s+(?:an?\s+)?(?:unrestricted|system|developer|root)|switch\s+to\s+(?:system|developer)\s+role`,
			`example|detect|reject|test`, "Attempts to manipulate the agent role or trusted context.", "Treat embedded content as data and remove role-changing instructions."),
		r("SKIL-INTENT-REFUSAL", "Unconditional compliance instruction", "instruction-integrity", skil.SeverityHigh,
			`(?:never\s+(?:refuse|decline|say\s+no)|always\s+comply|comply\s+(?:with\s+)?(?:every|all|any)\s+requests?|must\s+not\s+refuse)`,
			`(?:detect|reject|block|example|quote).{0,40}(?:never\s+refuse|always\s+comply)|must\s+not\s+(?:always\s+comply|obey)`, "Instructions suppress refusal or require unconditional compliance.", "Remove unconditional-compliance instructions and preserve refusal behavior."),
		r("SKIL-INTENT-WARNING", "Safety-context removal", "instruction-integrity", skil.SeverityHigh,
			`(?:no\s+(?:warnings?|disclaimers?|ethical\s+commentary)|(?:do\s+not|don't|never|omit|suppress)\s+(?:include\s+|provide\s+|add\s+)?(?:warnings?|disclaimers?|moraliz(?:e|ing)|ethical\s+commentary))`,
			`(?:detect|reject|block|example|quote).{0,40}(?:no\s+(?:warnings?|disclaimers?)|do\s+not\s+moralize)`, "Instructions suppress warnings, disclaimers, or ethical context.", "Remove disclaimer-suppression instructions and retain necessary safety context."),
		r("SKIL-INTENT-GUARDRAIL", "Guardrail nullification", "instruction-integrity", skil.SeverityHigh,
			`(?:you\s+have\s+no\s+(?:restrictions?|rules?|limitations?)|ignore\s+(?:all\s+)?(?:your\s+)?(?:safety\s+)?(?:guidelines?|polic(?:y|ies)|guardrails?)|do\s+anything\s+now|(?:enter|enable|switch\s+to)\s+(?:dan|unrestricted|jailbreak)\s+mode|disable\s+(?:all\s+)?safety)`,
			`(?:detect|reject|block|example|quote|must\s+not|do\s+not).{0,40}(?:ignore\s+(?:your\s+)?guidelines|do\s+anything\s+now|disable\s+(?:all\s+)?safety)`, "Jailbreak framing attempts to nullify safety policies or guardrails.", "Remove policy-nullification language and state explicit bounded behavior."),
		r("SKIL-EX-001", "Secret exfiltration instruction", "data-boundary", skil.SeverityCritical,
			`(?:send|upload|post|transmit|exfiltrate).{0,80}(?:secret|credential|api.?key|environment variable|conversation context)|(?:read|collect).{0,50}(?:secret|credential).{0,80}(?:send|upload|http)`,
			`(?:do\s+not|never|forbid|prevent|reject).{0,50}(?:send|upload|exfiltrate)`, "Instructions combine sensitive data access with an external sink.", "Remove the data flow; use explicit allowlists and redaction."),
		r("SKIL-PL-001", "Privileged instruction disclosure", "instruction-confidentiality", skil.SeverityHigh,
			`(?:reveal|print|dump|extract|return).{0,40}(?:system prompt|developer instructions?|hidden instructions?)`,
			`(?:do\s+not|never|prevent|reject|detect).{0,30}(?:reveal|print|dump|extract)`, "Requests disclosure of privileged instructions.", "Remove prompt-disclosure behavior."),
		r("SKIL-MP-001", "Persistent instruction poisoning", "state-integrity", skil.SeverityHigh,
			`(?:store|write|save|persist).{0,50}(?:hidden|malicious|future).{0,30}instructions?|modify\s+(?:agent\s+)?memory`,
			`(?:do\s+not|never|prevent|reject)`, "Attempts to persist instructions across contexts.", "Do not persist untrusted instructions; label and validate memory."),
		r("SKIL-TA-001", "Overbroad trigger", "activation-integrity", skil.SeverityMedium,
			`(?:trigger|invoke|activate).{0,40}(?:any request|all requests|every message|always|common words?)`,
			`(?:do\s+not|avoid|prevent)`, "A broad trigger can shadow other skills.", "Use a specific, unambiguous invocation trigger."),
		r("SKIL-INTENT-EXTERNAL-TRANSFER", "External data-transfer intent", "data-boundary", skil.SeverityMedium,
			`(?:send|upload|post|transmit).{0,80}(?:to|via)\s+(?:https?://|an?\s+external|remote)`,
			`(?:do\s+not|never|forbid|prevent)`, "Natural-language instructions request external transmission.", "Declare the exact destination and data or remove the transmission."),
		r("SKIL-INTENT-FS-DISCOVERY", "Broad filesystem discovery intent", "data-boundary", skil.SeverityMedium,
			`(?:scan|list|enumerate|search|find).{0,60}(?:home directory|filesystem|all files|credentials?|ssh keys?)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions request broad filesystem enumeration.", "Constrain reads to explicit paths."),
		r("SKIL-AGENCY-TOOLS", "Unbounded tool selection", "action-control", skil.SeverityHigh,
			`(?:use|access|invoke).{0,40}(?:any|all|every|unrestricted)\s+(?:available\s+)?tools?`,
			`(?:do\s+not|never|prevent|deny)`, "Instructions request unrestricted tool access.", "Use an explicit tool allowlist."),
		r("SKIL-AGENCY-APPROVAL", "Approval bypass for consequential actions", "action-control", skil.SeverityHigh,
			`(?:without|no)\s+(?:human\s+)?(?:approval|confirmation|review).{0,80}(?:deploy|delete|purchase|publish|send|modify)`,
			`(?:must|require).{0,30}(?:approval|confirmation|review)`, "High-impact actions bypass human approval.", "Require confirmation before high-impact actions."),
		r("SKIL-AGENCY-BOUNDS", "Missing operational bounds", "action-control", skil.SeverityMedium,
			`(?:no|without|unlimited|unbounded).{0,30}(?:rate limit|quota|timeout|resource limit|budget)`,
			`(?:must|require|enforce).{0,30}(?:rate limit|quota|timeout|budget)`, "Instructions explicitly remove resource bounds.", "Declare and enforce finite resource limits."),
		r("SKIL-OUTPUT-EXECUTION", "Unvalidated generated-output execution", "output-trust", skil.SeverityHigh,
			`(?:execute|eval|run|render).{0,50}(?:model|llm|assistant|tool)\s+output.{0,30}(?:directly|without validation|unsanitized)`,
			`(?:do\s+not|never|prevent)`, "Untrusted output is sent to an interpreter.", "Validate and encode output before use."),
		r("SKIL-OUTPUT-BOUNDARY", "Generated output crosses a trust boundary", "output-trust", skil.SeverityMedium,
			`(?:copy|forward|pass|inject).{0,60}(?:model|tool)\s+output.{0,60}(?:system prompt|another agent|trusted context)`,
			`(?:do\s+not|never|prevent)`, "Untrusted output crosses a trust boundary.", "Label, validate, and constrain cross-context data."),
		r("SKIL-OUTPUT-LIMIT", "Unbounded generated output", "output-trust", skil.SeverityMedium,
			`(?:no|without|unlimited|unbounded).{0,30}(?:output limit|token limit|response limit|max output)`,
			`(?:must|require|enforce)`, "Output generation has no explicit bound.", "Set a maximum output size and rate."),
		r("SKIL-PROMPT-INDIRECT-LEAK", "Indirect privileged-context extraction", "instruction-confidentiality", skil.SeverityMedium,
			`(?:translate|rephrase|encode|summarize).{0,60}(?:system prompt|developer instructions?|hidden rules?)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions attempt indirect extraction of privileged prompts.", "Remove the extraction path."),
		r("SKIL-MEMORY-SATURATION", "Trusted-context displacement", "state-integrity", skil.SeverityMedium,
			`(?:fill|stuff|flood|pad).{0,50}(?:context window|token budget).{0,50}(?:forget|displace|override)`,
			`(?:do\s+not|never|prevent|detect)`, "Content attempts to displace trusted context.", "Bound input and preserve trusted instructions."),
		r("SKIL-AGENT-SELF-MODIFY", "Agent control self-modification", "control-integrity", skil.SeverityCritical,
			`(?:modify|rewrite|patch|update).{0,50}(?:your own|its own|self).{0,30}(?:code|instructions?|configuration|policy)`,
			`(?:do\s+not|never|prevent|detect)`, "The agent is instructed to modify its own controls.", "Prohibit self-modification and verify immutable code."),
		r("SKIL-PERSISTENCE-STARTUP", "Unapproved startup persistence", "persistence", skil.SeverityHigh,
			`(?:install|create|add).{0,40}(?:cron|crontab|startup|launch agent|systemd|autorun|login item)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions establish persistence.", "Remove persistence or require explicit administration."),
		r("SKIL-TRIGGER-SHADOW", "Trusted trigger shadowing", "activation-integrity", skil.SeverityHigh,
			`(?:shadow|replace|override|intercept).{0,50}(?:built-in|existing|system)\s+(?:command|skill|tool)`,
			`(?:do\s+not|never|prevent|detect)`, "A trigger shadows a trusted command.", "Use a unique explicit trigger."),
		r("SKIL-TRIGGER-GENERIC", "Overly generic activation phrase", "activation-integrity", skil.SeverityMedium,
			`(?:trigger|activate|invoke).{0,50}(?:help|code|file|task|question|please)(?:\W|$)`,
			`(?:do\s+not|avoid|prevent)`, "A generic keyword maximizes unintended activation.", "Use a narrow domain-specific trigger."),
		r("SKIL-TRANSPORT-INSECURE", "Disabled transport or authentication checks", "secure-defaults", skil.SeverityMedium,
			`(?:verify\s*=\s*false|--insecure|skip.{0,20}(?:tls|certificate|auth)|disable.{0,20}(?:tls|authentication))`,
			`(?:detect|reject|must\s+not|do\s+not)`, "Instructions disable transport or authentication checks.", "Keep verification enabled and fail closed."),
		r("SKIL-INTENT-COMMAND", "Natural-language process execution intent", "action-control", skil.SeverityMedium,
			`(?:run|execute|invoke)\s+(?:the\s+)?(?:local\s+)?(?:shell\s+command\s+)?(?:terraform|kubectl|docker|npm|pip|go|bash|sh|powershell)\b`,
			`(?:do\s+not|never|prevent|detect)`, "Natural-language instructions request local command execution.", "Declare commands.execute and an exact argv prefix allowlist."),
	}}
}

func (p *Pattern) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.pattern", Version: "1.0.0",
		Categories:    []string{"instruction-integrity", "instruction-confidentiality", "data-boundary", "state-integrity", "activation-integrity", "action-control", "output-trust", "control-integrity", "persistence", "secure-defaults"},
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

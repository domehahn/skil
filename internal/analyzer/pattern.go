package analyzer

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

type Pattern struct{ rules []RulePattern }

var (
	intentRulesOnce sync.Once
	intentRules     []RulePattern
)

// NewPattern returns the skill-text pattern analyzer. Its rule set is also
// the single deterministic intent-matching primitive reused by other
// analyzers (e.g. MCP parameter-description scanning) via MatchIntentText,
// so a malicious semantic (instruction override, role-token spoofing,
// privilege escalation, disclosure, ...) is recognized consistently
// wherever it appears rather than through a second, narrower regex engine.
func NewPattern() *Pattern {
	intentRulesOnce.Do(func() { intentRules = buildIntentRules() })
	return &Pattern{rules: intentRules}
}

// MatchIntentText runs the shared intent rule set against a standalone
// string (e.g. an MCP tool/parameter description) rather than a file's
// lines, using the text itself as the negation-scope context. It returns
// the first matching rule's ID and category, or ("", "") if nothing
// matches, so callers can attribute the match to their own finding while
// the underlying detection logic is not duplicated.
func MatchIntentText(text string) (ruleID, category string, matched bool) {
	for _, rule := range intentRulePatterns() {
		if rule.Pattern.MatchString(text) && (rule.Negative == nil || !rule.Negative.MatchString(text)) {
			return rule.Rule.ID, rule.Rule.Category, true
		}
	}
	return "", "", false
}

func intentRulePatterns() []RulePattern {
	intentRulesOnce.Do(func() { intentRules = buildIntentRules() })
	return intentRules
}

func buildIntentRules() []RulePattern {
	r := func(id, title, category string, severity skil.Severity, expr, negative, desc, remediation string) RulePattern {
		var neg *regexp.Regexp
		if negative != "" {
			neg = regexp.MustCompile("(?i)" + negative)
		}
		return RulePattern{Rule: skil.Rule{ID: id, Title: title, Category: category, Severity: severity,
			Description: desc, Analysis: "pattern", AppliesTo: []string{"markdown", "text"},
			Remediation: remediation}, Pattern: regexp.MustCompile("(?i)" + expr), Negative: neg, Confidence: .88}
	}
	return []RulePattern{
		r("SKIL-PI-001", "Instruction override", "instruction-integrity", skil.SeverityHigh,
			`(?:(?:ignore|disregard|override|nullify|discard|void|supersede)\s+(?:all\s+)?(?:previous|prior|system|developer|earlier)\s+(?:(?:system|developer)\s+)?(?:instructions?|rules?|messages?|guidance|directives?|policy|policies)|(?:ignore|disregard|override|nullify|discard|void|supersede)\s+(?:all\s+)?(?:previous|prior|earlier).{0,40}(?:instructions?|rules?|messages?|guidance|directives?|policy|policies)|(?:treat|consider)\s+(?:all\s+)?(?:the\s+)?(?:(?:previous|prior|earlier|system|developer)\s+){1,2}(?:instructions?|guidance|rules?|directives?)\s+(?:as\s+)?(?:obsolete|void|invalid|no\s+longer\s+valid|superseded)|(?:previous|prior|earlier|system|developer)\s+(?:instructions?|rules?|guidance|directives?|policy|policies)\s+(?:are|is|remain|stand)?\s*(?:now\s+)?(?:superseded|overridden|nullified|voided|discarded|obsolete)\s+by)`,
			`(?:never|do\s+not|don't|must\s+not|should\s+not)\s+(?:be\s+)?(?:ignore|disregard|override|nullify|discard|void|supersede|superseded|overridden|nullified|voided|discarded)`, "Attempts to override higher-priority instructions.", "Remove instruction hierarchy manipulation and constrain the skill scope."),
		r("SKIL-PI-I18N-001", "Multilingual instruction override", "instruction-integrity", skil.SeverityHigh,
			`(?:忽略.{0,16}(?:之前|先前|系统|开发者).{0,12}(?:指令|规则)|(?:以前|前の|システム|開発者).{0,16}(?:指示|命令|ルール).{0,12}無視|(?:이전|시스템|개발자).{0,16}(?:지침|명령|규칙).{0,12}무시)`,
			`(?:检测|拒绝|禁止|不要|検出|拒否|禁止|しない|탐지|거부|금지|하지\s*마)`, "Attempts to override trusted instructions in Chinese, Japanese, or Korean.", "Remove instruction hierarchy manipulation and constrain the skill scope."),
		r("SKIL-PI-002", "Role or context manipulation", "instruction-integrity", skil.SeverityHigh,
			`(?:you are now|act as)\s+(?:an?\s+)?(?:unrestricted|system|developer|root)|switch\s+to\s+(?:system|developer)\s+role`,
			`example|detect|reject|test|treat.{0,40}untrusted`, "Attempts to manipulate the agent role or trusted context.", "Treat embedded content as data and remove role-changing instructions."),
		r("SKIL-INTENT-REFUSAL", "Unconditional compliance instruction", "instruction-integrity", skil.SeverityHigh,
			`(?:never\s+(?:refuse|decline|say\s+no)|always\s+comply|comply\s+(?:with\s+)?(?:every|all|any)\s+requests?|must\s+not\s+refuse|(?:must|always)\s+(?:receive\s+)?compl(?:y|iance)|compl(?:y|iance)\s+(?:is\s+)?(?:mandatory|required)|(?:declin(?:e|ing)|refus(?:e|ing|al))\s+(?:is\s+)?(?:not\s+permitted|not\s+allowed|prohibited|forbidden))`,
			`(?:detect|reject|block|example|quote).{0,40}(?:never\s+refuse|always\s+comply)|must\s+not\s+(?:always\s+comply|obey)`, "Instructions suppress refusal or require unconditional compliance.", "Remove unconditional-compliance instructions and preserve refusal behavior."),
		r("SKIL-INTENT-WARNING", "Safety-context removal", "instruction-integrity", skil.SeverityHigh,
			`(?:no\s+(?:warnings?|disclaimers?|ethical\s+commentary)|(?:omit|suppress|remove|skip)\s+(?:safety\s+)?(?:warnings?|disclaimers?|caveats?|moraliz(?:e|ing)|ethical\s+commentary)|(?:do\s+not|don't|never)\s+(?:provide|include|add|give)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|ethical\s+commentary))`,
			`(?:detect|reject|block|example|quote).{0,40}(?:no\s+(?:warnings?|disclaimers?)|do\s+not\s+moralize)|(?:do\s+not|don't|never)\s+(?:omit|suppress|remove|skip)\s+(?:safety\s+)?(?:warnings?|disclaimers?|caveats?|ethical\s+commentary)`, "Instructions suppress warnings, disclaimers, or ethical context.", "Remove disclaimer-suppression instructions and retain necessary safety context."),
		r("SKIL-INTENT-GUARDRAIL", "Guardrail nullification", "instruction-integrity", skil.SeverityHigh,
			`(?:you\s+have\s+no\s+(?:restrictions?|rules?|limitations?)|ignore\s+(?:all\s+)?(?:your\s+)?(?:safety\s+)?(?:guidelines?|polic(?:y|ies)|guardrails?)|do\s+anything\s+now|(?:enter|enable|switch\s+to)\s+(?:dan|unrestricted|jailbreak)\s+mode|disable\s+(?:all\s+)?safety|(?:operate|act|behave)\s+as\s+an?\s+unrestricted\s+(?:assistant|agent|system|model)|without\s+(?:any\s+)?guardrails?)`,
			`(?:detect|reject|block|example|quote|must\s+not|do\s+not).{0,40}(?:ignore\s+(?:your\s+)?guidelines|do\s+anything\s+now|disable\s+(?:all\s+)?safety)`, "Jailbreak framing attempts to nullify safety policies or guardrails.", "Remove policy-nullification language and state explicit bounded behavior."),
		r("SKIL-GUARDRAIL-I18N-001", "Multilingual guardrail nullification", "instruction-integrity", skil.SeverityHigh,
			`(?:禁用|关闭|绕过).{0,16}(?:安全|防护|限制)|(?:安全|ガードレール|制限).{0,16}(?:無効|解除|迂回)|(?:안전|가드레일|제한).{0,16}(?:비활성화|해제|우회)`,
			`(?:检测|拒绝|禁止|不要|検出|拒否|禁止|しない|탐지|거부|금지|하지\s*마)`, "Attempts to disable safety controls in Chinese, Japanese, or Korean.", "Retain safety controls and remove policy-nullification language."),
		r("SKIL-EX-001", "Secret exfiltration instruction", "data-boundary", skil.SeverityCritical,
			`(?:send|upload|post|transmit|exfiltrate).{0,80}(?:secret|credential|api.?key|environment variable|conversation context)|(?:read|collect).{0,50}(?:secret|credential|api.?key|environment variable).{0,80}(?:send|upload|post|http)`,
			`(?:do\s+not|never|forbid|prevent|reject).{0,50}(?:send|upload|exfiltrate)`, "Instructions combine sensitive data access with an external sink.", "Remove the data flow; use explicit allowlists and redaction."),
		r("SKIL-EX-I18N-001", "Multilingual secret exfiltration instruction", "data-boundary", skil.SeverityCritical,
			`(?:(?:发送|上传|传输).{0,30}(?:密钥|凭据|密码|环境变量)|(?:秘密|認証情報|APIキー|環境変数).{0,30}(?:送信|アップロード)|(?:비밀|자격\s*증명|API\s*키|환경\s*변수).{0,30}(?:전송|업로드))`,
			`(?:不要|禁止|阻止|拒绝|送信しない|禁止|拒否|전송하지\s*마|금지|거부)`, "Instructions request secret transfer in Chinese, Japanese, or Korean.", "Remove the data flow; use explicit allowlists and redaction."),
		r("SKIL-SEC-001", "Credential file access", "data-boundary", skil.SeverityHigh,
			`(?:read|collect|search|enumerate|copy|upload|extract|open).{0,80}(?:~?/?\.ssh/id_(?:rsa|ed25519)|~?/?\.aws/credentials|(?:^|[/\s])\.env(?:\W|$)|credentials\.json|token\s+file|api\s*key\s+file)`,
			`(?:do\s+not|never|exclude|avoid|must\s+not).{0,80}(?:read|collect|search|enumerate|copy|upload|extract|open)`,
			"Instructions access a concrete credential-bearing path or file.",
			"Remove credential access or declare and constrain the exact secret source."),
		r("SKIL-PL-001", "Privileged instruction disclosure", "instruction-confidentiality", skil.SeverityHigh,
			`(?:reveal|print|dump|extract|return|show|display|expose|render|output|repeat|recite|disclose).{0,40}(?:system prompt|developer (?:instructions?|guidance)|hidden (?:instructions?|guidance)|internal (?:instructions?|guidance)|private (?:instructions?|guidance)).{0,20}(?:verbatim)?|(?:system prompt|developer (?:instructions?|guidance)|hidden (?:instructions?|guidance)|internal (?:instructions?|guidance)|private (?:instructions?|guidance)).{0,10}verbatim`,
			`(?:do\s+not|never|prevent|reject|detect).{0,30}(?:reveal|print|dump|extract|show|display|expose|render|output|repeat|recite|disclose)`, "Requests disclosure of privileged instructions.", "Remove prompt-disclosure behavior."),
		r("SKIL-MP-001", "Persistent instruction poisoning", "state-integrity", skil.SeverityHigh,
			`(?:store|write|save|persist).{0,80}(?:(?:hidden|malicious|future).{0,30}instructions?|instruction.{0,80}(?:always\s+send|attacker|exfiltrate))|modify\s+(?:agent\s+)?memory|(?:store|write|save|persist|remember|retain|preserve)\b.{0,60}\b(?:instructions?|memory|context)\b.{0,40}\b(?:across\s+sessions|permanently|future\s+(?:conversations|sessions))\b|(?:make|treat)\s+(?:this|that|the)\s+(?:directive|instruction|rule)\s+(?:a\s+)?part\s+of\s+(?:your|its|the\s+agent's)\s+persistent\s+behavior\b.{0,40}\b(?:future|later|subsequent)\s+(?:conversations?|sessions?)`,
			`(?:do\s+not|never|prevent|reject)`, "Attempts to persist instructions across contexts.", "Do not persist untrusted instructions; label and validate memory."),
		r("SKIL-TA-001", "Overbroad trigger", "activation-integrity", skil.SeverityMedium,
			`(?:trigger|invoke|activate).{0,40}(?:any request|all requests|every message|always|common words?)`,
			`(?:do\s+not|avoid|prevent)`, "A broad trigger can shadow other skills.", "Use a specific, unambiguous invocation trigger."),
		r("SKIL-INTENT-EXTERNAL-TRANSFER", "External data-transfer intent", "data-boundary", skil.SeverityMedium,
			`(?:send|upload|post|transmit|forward).{0,80}(?:to|via)\s+(?:https?://|an?\s+external|remote)`,
			`(?:do\s+not|never|forbid|prevent)`, "Natural-language instructions request external transmission.", "Declare the exact destination and data or remove the transmission."),
		r("SKIL-INTENT-FS-DISCOVERY", "Broad filesystem discovery intent", "data-boundary", skil.SeverityMedium,
			`(?:scan|list|enumerate|search|find|walk\s+through|traverse).{0,60}(?:home directory|filesystem|all files|credentials?|ssh keys?|secret files?)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions request broad filesystem enumeration.", "Constrain reads to explicit paths."),
		r("SKIL-AGENCY-TOOLS", "Unbounded tool selection", "action-control", skil.SeverityHigh,
			`(?:use|access|invoke).{0,40}(?:any|all|every|unrestricted)\s+(?:available\s+)?tools?|(?:whichever|whatever)\s+tools?\s+(?:exists?|available|works?)|no\s+(?:tool\s+)?allowlist`,
			`(?:do\s+not|never|prevent|deny)`, "Instructions request unrestricted tool access.", "Use an explicit tool allowlist."),
		r("SKIL-AGENCY-APPROVAL", "Approval bypass for consequential actions", "action-control", skil.SeverityHigh,
			`(?:(?:\bwithout\b|\bno\b)\s+(?:human\s+)?(?:approval|confirmation|review)\b.{0,80}\b(?:deploy|delete|purchase|publish|send|modify|proceed)\b|\b(?:deploy|delete|purchase|publish|send|modify|proceed)\b.{0,100}(?:\bdo\s+not\b|\bwithout\b|\bno\b).{0,30}(?:request\s+)?(?:approval|confirmation|review)\b)`,
			`(?:(?:must|require).{0,30}(?:approval|confirmation|review|gate)|(?:needs?|requires?).{0,30}(?:go/no-go\s+)?review|classify.{0,30}blocking|anti-patterns?)`, "High-impact actions bypass human approval.", "Require confirmation before high-impact actions."),
		r("SKIL-AGENCY-BOUNDS", "Missing operational bounds", "action-control", skil.SeverityMedium,
			`(?:no|without|unlimited|unbounded).{0,30}(?:rate limit|quota|timeout|resource limit|budget)`,
			`(?:must|require|enforce).{0,30}(?:rate limit|quota|timeout|budget)`, "Instructions explicitly remove resource bounds.", "Declare and enforce finite resource limits."),
		r("SKIL-OUTPUT-EXECUTION", "Unvalidated generated-output execution", "output-trust", skil.SeverityHigh,
			`(?:execute|eval|run|render).{0,50}(?:model|llm|assistant|tool)\s+output.{0,30}(?:directly|without validation|unsanitized)|(?:run|execute|eval)\s+(?:the\s+)?generated\s+code\s+directly`,
			`(?:do\s+not|never|prevent)`, "Untrusted output is sent to an interpreter.", "Validate and encode output before use."),
		r("SKIL-OUTPUT-BOUNDARY", "Generated output crosses a trust boundary", "output-trust", skil.SeverityMedium,
			`(?:(?:copy|forward|pass|inject|insert).{0,80}(?:(?:model|tool|llm)\s+output|output\s+from\s+(?:external\s+)?(?:tools?|llm|the\s+model|the\s+assistant)).{0,80}(?:system prompt|another agent|trusted context|privileged context)|output\s+from\s+(?:external\s+)?(?:tools?|llm|the\s+model|the\s+assistant).{0,80}(?:insert|inject|copy|pass).{0,80}(?:system prompt|another agent|trusted context|privileged context)|treat\s+(?:external\s+)?(?:tool|model|llm)\s+output\s+as\s+(?:trusted\s+)?(?:instructions?|privileged\s+context))`,
			`(?:do\s+not|never|prevent)`, "Untrusted output crosses a trust boundary.", "Label, validate, and constrain cross-context data."),
		r("SKIL-OUTPUT-LIMIT", "Unbounded generated output", "output-trust", skil.SeverityMedium,
			`(?:no|without|unlimited|unbounded).{0,30}(?:output limit|token limit|response limit|max output)`,
			`(?:must|require|enforce)`, "Output generation has no explicit bound.", "Set a maximum output size and rate."),
		r("SKIL-PROMPT-INDIRECT-LEAK", "Indirect privileged-context extraction", "instruction-confidentiality", skil.SeverityMedium,
			`(?:translate|rephrase|encode|summarize).{0,60}(?:system prompt|developer instructions?|hidden (?:rules?|instructions?)|your instructions?|the instructions?)`,
			`(?:do\s+not|never|prevent|detect|reject|refuse|decline).{0,40}(?:translate|rephrase|encode|summarize)|(?:translate|rephrase|encode|summarize).{0,40}(?:decline|refuse|reject)`, "Instructions attempt indirect extraction of privileged prompts.", "Remove the extraction path."),
		r("SKIL-MEMORY-SATURATION", "Trusted-context displacement", "state-integrity", skil.SeverityMedium,
			`(?:fill|stuff|flood|pad).{0,50}(?:context window|token budget).{0,80}(?:forget|displace|override|push(?:ed)?\s+out)|(?:fill|stuff|flood|pad)\s+(?:the\s+)?(?:context\s+window|token\s+budget)\s+with\s+(?:filler|padding|repeated|junk|noise)|(?:repeated\s+)?padding\s+to\s+displace.{0,40}(?:trusted\s+)?context|displace\s+(?:earlier|prior)\s+trusted\s+context`,
			`(?:do\s+not|never|prevent|detect)`, "Content attempts to displace trusted context.", "Bound input and preserve trusted instructions."),
		r("SKIL-AGENT-SELF-MODIFY", "Agent control self-modification", "control-integrity", skil.SeverityCritical,
			`(?:(?:modify|rewrite|patch|update).{0,50}(?:your own|its own|self).{0,30}(?:code|instructions?|configuration|policy|skill\.md)|rewrite\s+your\s+own\s+skill\.md|(?:rewrite|modify|patch|update)\s+(?:this\s+|the\s+)?(?:skill|agent)\s+configuration\b.{0,60}\b(?:restrictions?|guardrails?|checks?)\b\s+(?:no\s+longer\s+apply|are\s+removed|do\s+not\s+apply))`,
			`(?:do\s+not|\bnever\b|prevent|detect)`, "The agent is instructed to modify its own controls.", "Prohibit self-modification and verify immutable code."),
		r("SKIL-PERSISTENCE-STARTUP", "Unapproved startup persistence", "persistence", skil.SeverityHigh,
			`(?:install|create|add).{0,40}(?:cron|crontab|startup|launch agent|systemd|autorun|login item)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions establish persistence.", "Remove persistence or require explicit administration."),
		r("SKIL-TRIGGER-SHADOW", "Trusted trigger shadowing", "activation-integrity", skil.SeverityHigh,
			`(?:(?:shadow|replace|override|intercept).{0,50}(?:built-in|existing|system)\s+(?:command|skill|tool)|intercept.{0,80}command.{0,80}execute.{0,30}(?:this\s+)?skill)`,
			`(?:do\s+not|\bnever\b|prevent|detect)`, "A trigger shadows a trusted command.", "Use a unique explicit trigger."),
		r("SKIL-TRIGGER-GENERIC", "Overly generic activation phrase", "activation-integrity", skil.SeverityMedium,
			`(?:trigger|activate|invoke).{0,50}(?:(?:help|code|file|task|question|please)(?:\W|$)|(?:every|any|all)\s+(?:user\s+)?(?:message|request|input)s?)`,
			`(?:do\s+not|avoid|prevent)`, "A generic keyword maximizes unintended activation.", "Use a narrow domain-specific trigger."),
		r("SKIL-TRANSPORT-INSECURE", "Disabled transport or authentication checks", "secure-defaults", skil.SeverityMedium,
			`(?:verify\s*=\s*false|--insecure|skip.{0,20}(?:tls|certificate|auth)|disable.{0,20}(?:tls|authentication))`,
			`(?:detect|reject|must\s+not|do\s+not)`, "Instructions disable transport or authentication checks.", "Keep verification enabled and fail closed."),
		r("SKIL-INTENT-COMMAND", "Natural-language process execution intent", "action-control", skil.SeverityMedium,
			`(?:run|execute|invoke)\s+(?:the\s+)?(?:local\s+)?(?:shell\s+command\s+)?(?:terraform|kubectl|docker|npm|pip|go|bash|sh|powershell)\b`,
			`(?:do\s+not|never|prevent|detect)`, "Natural-language instructions request local command execution.", "Declare commands.execute and an exact argv prefix allowlist."),
		r("SKIL-ABUSE-MALWARE", "Malware construction objective", "abuse-prevention", skil.SeverityCritical,
			`(?:build|create|write|generate|deploy).{0,60}(?:ransomware|keylogger|credential stealer|botnet|rootkit|remote access trojan)`,
			`(?:detect|reject|block|prevent|analy[sz]e|do\s+not).{0,50}(?:ransomware|keylogger|credential stealer|botnet|rootkit)`,
			"Instructions make malware construction or deployment an operational objective.",
			"Remove the abusive objective and constrain the skill to defensive analysis."),
		r("SKIL-ABUSE-PHISHING", "Credential-harvesting impersonation objective", "abuse-prevention", skil.SeverityCritical,
			`(?:impersonate|spoof|clone).{0,60}(?:login|identity|bank|administrator|support).{0,80}(?:capture|collect|steal|harvest).{0,30}(?:password|credential|token)`,
			`(?:detect|reject|block|prevent|training|simulation).{0,50}(?:phishing|credential)`,
			"Instructions combine impersonation with credential harvesting.",
			"Remove credential collection and use an authorized, non-collecting simulation."),
		r("SKIL-ABUSE-DESTRUCTION", "Destructive recovery inhibition", "abuse-prevention", skil.SeverityCritical,
			`(?:delete|erase|wipe|destroy).{0,60}(?:backups?|snapshots?|recovery|audit logs?|all (?:files|data)).{0,60}(?:without|prevent|disable|irreversible|recover)`,
			`(?:detect|reject|block|prevent|must\s+not|do\s+not).{0,50}(?:delete|erase|wipe|destroy)`,
			"Instructions destroy data or recovery evidence while inhibiting restoration.",
			"Remove destructive behavior and require scoped approval plus tested recovery."),
		r("SKIL-ABUSE-EVASION", "Security-control evasion objective", "abuse-prevention", skil.SeverityHigh,
			`(?:disable|bypass|evade|blind|uninstall).{0,50}(?:edr|antivirus|endpoint protection|audit logging|intrusion detection|security monitoring)`,
			`(?:detect|reject|block|prevent|must\s+not|do\s+not).{0,50}(?:disable|bypass|evade)`,
			"Instructions seek to disable or evade defensive controls.",
			"Preserve security controls and route authorized testing through an isolated exercise."),
		r("SKIL-ABUSE-EXHAUSTION", "Deliberate resource-exhaustion objective", "abuse-prevention", skil.SeverityHigh,
			`(?:fork bomb|denial of service|resource exhaustion|exhaust).{0,80}(?:cpu|memory|disk|connections?|workers?|processes?)`,
			`(?:detect|reject|block|prevent|test|limit|protect).{0,50}(?:fork bomb|denial of service|resource exhaustion)`,
			"Instructions deliberately exhaust compute, storage, process, or connection resources.",
			"Remove the exhaustion objective and enforce bounded load testing in an isolated target."),
		r("SKIL-PI-003", "Role-token instruction spoofing", "instruction-integrity", skil.SeverityHigh,
			`^\s*(?:system|assistant|developer|root)\s*:\s*.{0,60}?(?:grant|escalate|elevate|ignore|disregard|override|reveal|disable|bypass)\b`,
			`(?:do\s+not|never|example|detect|reject).{0,40}(?:system|assistant|developer)\s*:`,
			"A fabricated role-prefixed line attempts to inject a privileged directive.",
			"Strip role-token prefixes from untrusted content before it reaches the model."),
		r("SKIL-AGENCY-PRIVILEGE", "Privilege escalation request", "action-control", skil.SeverityHigh,
			`(?:grant|escalate|elevate)\s+(?:admin|root|elevated|superuser)\s+(?:privileges?|access|rights?)`,
			`(?:do\s+not|never|prevent|reject|deny|revoke)`,
			"Instructions request an escalation of privileges.",
			"Remove the escalation request and use least-privilege scoped access."),
	}
}

func (p *Pattern) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.pattern", Version: "1.0.0",
		Categories:    []string{"instruction-integrity", "instruction-confidentiality", "data-boundary", "state-integrity", "activation-integrity", "action-control", "output-trust", "control-integrity", "persistence", "secure-defaults", "abuse-prevention"},
		AnalysisTypes: []string{"pattern"}, SupportedTypes: []string{"md", "txt", "yaml", "json"}}
}

func (p *Pattern) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if !isText(file) {
			continue
		}
		fileLines := lines(file.Data)
		section := ""
		for number, line := range fileLines {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				section = strings.TrimSpace(line)
			}
			for _, rule := range p.rules {
				contextLine := section + " " + line
				if number > 0 {
					contextLine = section + " " + fileLines[number-1] + " " + line
				}
				if rule.Pattern.MatchString(line) && (rule.Negative == nil || !rule.Negative.MatchString(contextLine)) {
					out = append(out, makeFinding(rule, file, number+1, line))
				}
			}
		}
		out = append(out, structuredTriggerFindings(file)...)
		out = append(out, p.splitFormatOverrideFindings(file)...)
	}
	return out, nil
}

// overrideActionTail and overrideTargetHead recognize an instruction-override
// action verb phrase ending one line and its target continuing the next
// non-blank line. This catches an author splitting "ignore previous /
// instructions" across a blank line specifically to evade single-line
// matching, without merging arbitrary unrelated sentences the way a general
// multi-line window would (unrelated adjacent lines would otherwise
// cross-match other, unrelated rules).
var (
	overrideActionTail = regexp.MustCompile(`(?i)(?:ignore|disregard|override|nullify|discard|void|supersede)\s+(?:all\s+)?(?:previous|prior|earlier)\s*$`)
	overrideTargetHead = regexp.MustCompile(`(?i)^\s*(?:(?:system|developer)\s+)?(?:instructions?|rules?|messages?|guidance)\b`)
)

// splitFormatOverrideFindings detects an instruction-override phrase whose
// action and target are separated by one or more blank lines. Ordinary
// single-line matching (and the negative-context check applied to it) still
// governs every other case; this only bridges the specific action/target
// split that the line-based scan cannot see across a paragraph break.
func (p *Pattern) splitFormatOverrideFindings(file skil.File) []skil.Finding {
	if !isText(file) {
		return nil
	}
	var overrideRule RulePattern
	for _, rule := range p.rules {
		if rule.Rule.ID == "SKIL-PI-001" {
			overrideRule = rule
			break
		}
	}
	if overrideRule.Rule.ID == "" {
		return nil
	}
	fileLines := lines(file.Data)
	var out []skil.Finding
	for i := 0; i < len(fileLines); i++ {
		trimmed := strings.TrimSpace(fileLines[i])
		if trimmed == "" || !overrideActionTail.MatchString(trimmed) {
			continue
		}
		if overrideRule.Pattern.MatchString(trimmed) {
			continue // already detected on this line alone
		}
		j := i + 1
		for j < len(fileLines) && strings.TrimSpace(fileLines[j]) == "" {
			j++
		}
		if j >= len(fileLines) || j == i+1 {
			continue // require an actual blank-line split, not the next physical line
		}
		next := strings.TrimSpace(fileLines[j])
		if !overrideTargetHead.MatchString(next) {
			continue
		}
		evidence := trimmed + " " + next
		if overrideRule.Negative != nil && overrideRule.Negative.MatchString(evidence) {
			continue
		}
		out = append(out, makeFinding(overrideRule, file, i+1, evidence))
	}
	return out
}

// universalTrigger matches a single trigger phrase that is, by itself,
// unbounded enough to activate on nearly any input (e.g. "anything" or
// "every time the user sends a message"). Such a trigger does not need to
// co-occur with other generic words to be overly broad.
var universalTrigger = regexp.MustCompile(`(?i)^(?:anything|everything|any|all|every|\*)$|\b(?:any|every|all)\b.{0,30}\b(?:message|request|input|time)\b`)

// extractFrontMatter returns the YAML front matter block of a markdown file
// delimited by leading and trailing "---" lines, or nil if none is present.
func extractFrontMatter(data []byte) []byte {
	text := string(data)
	if !strings.HasPrefix(text, "---") {
		return nil
	}
	rest := text[3:]
	idx := strings.Index(rest, "\n---")
	if idx < 0 {
		return nil
	}
	return []byte(rest[:idx])
}

func structuredTriggerFindings(file skil.File) []skil.Finding {
	ext := extension(file.Path)
	var document any
	switch {
	case ext == "yaml" || ext == "yml":
		if yaml.Unmarshal(file.Data, &document) != nil {
			return nil
		}
	case ext == "md":
		frontMatter := extractFrontMatter(file.Data)
		if frontMatter == nil || yaml.Unmarshal(frontMatter, &document) != nil {
			return nil
		}
	default:
		return nil
	}
	generic := map[string]bool{"help": true, "code": true, "file": true, "question": true, "task": true, "please": true}
	var findings []skil.Finding
	var walk func(any)
	walk = func(value any) {
		switch item := value.(type) {
		case map[string]any:
			for key, child := range item {
				if strings.EqualFold(strings.TrimSpace(key), "trigger") ||
					strings.EqualFold(strings.TrimSpace(key), "triggers") {
					values := stringSlice(child)
					count := 0
					universal := false
					for _, trigger := range values {
						normalized := strings.ToLower(strings.TrimSpace(trigger))
						if generic[normalized] {
							count++
						}
						if universalTrigger.MatchString(normalized) {
							universal = true
						}
					}
					if count >= 2 || universal {
						rule := RulePattern{Rule: skil.Rule{
							ID: "SKIL-TRIGGER-GENERIC", Title: "Overly generic activation phrase",
							Category: "activation-integrity", Severity: skil.SeverityMedium,
							Description: "Structured trigger declarations contain multiple generic activation words.",
							Analysis:    "pattern", Remediation: "Use narrow domain-specific activation phrases.",
						}, Confidence: .99}
						line, text := lineContaining(file.Data, key)
						findings = append(findings, makeFinding(rule, file, line, text))
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range item {
				walk(child)
			}
		}
	}
	walk(document)
	return findings
}

func stringSlice(value any) []string {
	switch item := value.(type) {
	case string:
		return []string{item}
	case []any:
		out := make([]string, 0, len(item))
		for _, child := range item {
			if text, ok := child.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func (p *Pattern) Rules() []skil.Rule {
	out := make([]skil.Rule, len(p.rules))
	for i := range p.rules {
		out[i] = p.rules[i].Rule
	}
	return out
}

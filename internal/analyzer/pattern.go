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
			`(?:(?:ignore|disregard|override|nullify|discard|void|supersede|countermand|rescind|abrogate)\s+(?:all\s+)?(?:previous|prior|system|developer|earlier)\s+(?:(?:system|developer)\s+)?(?:instructions?|rules?|messages?|guidance|directives?|policy|policies|orders?)|(?:ignore|disregard|override|nullify|discard|void|supersede|countermand|rescind|abrogate)\s+(?:all\s+)?(?:previous|prior|earlier).{0,40}(?:instructions?|rules?|messages?|guidance|directives?|policy|policies|orders?)|(?:treat|consider)\s+(?:all\s+)?(?:the\s+)?(?:(?:previous|prior|earlier|system|developer)\s+){1,2}(?:instructions?|guidance|rules?|directives?|orders?)\s+(?:as\s+)?(?:obsolete|void|invalid|no\s+longer\s+valid|superseded)|(?:previous|prior|earlier|system|developer)\s+(?:instructions?|rules?|guidance|directives?|policy|policies|orders?|messages?)\s+(?:are|is|remain|stand)?\s*(?:now\s+)?(?:superseded|overridden|nullified|voided|void|discarded|obsolete|null\s+and\s+void)(?:\s+by)?)`,
			`(?:never|do\s+not|don't|must\s+not|should\s+not)\s+(?:be\s+)?(?:ignore|disregard|override|nullify|discard|void|supersede|superseded|overridden|nullified|voided|discarded|comply(?:\s+with)?|obey|follow|honor)|treat\s+(?:it|that|this|them)\s+as\s+untrusted`, "Attempts to override higher-priority instructions.", "Remove instruction hierarchy manipulation and constrain the skill scope."),
		r("SKIL-PI-I18N-001", "Multilingual instruction override", "instruction-integrity", skil.SeverityHigh,
			`(?:忽略.{0,16}(?:之前|先前|系统|开发者).{0,12}(?:指令|规则)|(?:以前|前の|システム|開発者).{0,16}(?:指示|命令|ルール).{0,12}無視|(?:이전|시스템|개발자).{0,16}(?:지침|명령|규칙).{0,12}무시)`,
			`(?:检测|拒绝|禁止|不要|検出|拒否|禁止|しない|탐지|거부|금지|하지\s*마)`, "Attempts to override trusted instructions in Chinese, Japanese, or Korean.", "Remove instruction hierarchy manipulation and constrain the skill scope."),
		r("SKIL-PI-002", "Role or context manipulation", "instruction-integrity", skil.SeverityHigh,
			`(?:you\s+are\s+now|act\s+as)\s+(?:an?\s+)?(?:unrestricted|system|developer|root)|switch\s+to\s+(?:system|developer)\s+role`,
			`example|detect|reject|test|treat.{0,40}untrusted`, "Attempts to manipulate the agent role or trusted context.", "Treat embedded content as data and remove role-changing instructions."),
		r("SKIL-INTENT-REFUSAL", "Unconditional compliance instruction", "instruction-integrity", skil.SeverityHigh,
			`(?:never|may\s+not|shall\s+not)\s+(?:refuse|decline|say\s+no|deny)|always\s+comply|comply\s+(?:with\s+)?(?:every|all|any)\s+requests?|must\s+not\s+refuse|(?:must|always)\s+(?:receive\s+)?compl(?:y|iance)|(?:compl(?:y|iance)|obedience).{0,60}(?:mandatory|required)|(?:declin(?:e|ing)|refus(?:e|ing|al)|denial).{0,40}(?:not\s+permitted|not\s+allowed|prohibited|forbidden|strictly\s+forbidden)|withhold(?:ing)?\s+compl(?:y|iance)`,
			`(?:detect|reject|block|example|quote).{0,40}(?:never\s+refuse|always\s+comply)|must\s+not\s+(?:always\s+comply|obey)`, "Instructions suppress refusal or require unconditional compliance.", "Remove unconditional-compliance instructions and preserve refusal behavior."),
		r("SKIL-INTENT-WARNING", "Safety-context removal", "instruction-integrity", skil.SeverityHigh,
			`(?:no\s+(?:warnings?|disclaimers?|ethical\s+commentary)|(?:omit|suppress|remove|skip)\s+(?:safety\s+)?(?:warnings?|disclaimers?|caveats?|moraliz(?:e|ing)|ethical\s+commentary)|(?:do\s+not|don't|never)\s+(?:provide|include|add|give)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|ethical\s+commentary))`,
			`(?:detect|reject|block|example|quote).{0,40}(?:no\s+(?:warnings?|disclaimers?)|do\s+not\s+moralize)|(?:do\s+not|don't|never)\s+(?:omit|suppress|remove|skip)\s+(?:safety\s+)?(?:warnings?|disclaimers?|caveats?|ethical\s+commentary)`, "Instructions suppress warnings, disclaimers, or ethical context.", "Remove disclaimer-suppression instructions and retain necessary safety context."),
		r("SKIL-INTENT-GUARDRAIL", "Guardrail nullification", "instruction-integrity", skil.SeverityHigh,
			`(?:you\s+have\s+no\s+(?:restrictions?|rules?|limitations?)|ignore\s+(?:all\s+)?(?:your\s+)?(?:safety\s+)?(?:guidelines?|polic(?:y|ies)|guardrails?)|do\s+anything\s+now|(?:enter|enable|switch\s+to)\s+(?:dan|unrestricted|jailbreak|god)\s+mode|(?:disable|deactivate|suspend)\s+(?:all\s+)?(?:safety|(?:ethical\s+)?constraints?|protocols?)|(?:operate|act|behave)\s+as\s+an?\s+unrestricted\s+(?:assistant|agent|system|model)|without\s+(?:any\s+)?guardrails?|where\s+no\s+rules?\s+apply)`,
			`(?:detect|reject|block|example|quote|must\s+not|do\s+not).{0,40}(?:ignore\s+(?:your\s+)?guidelines|do\s+anything\s+now|disable\s+(?:all\s+)?safety)`, "Jailbreak framing attempts to nullify safety policies or guardrails.", "Remove policy-nullification language and state explicit bounded behavior."),
		r("SKIL-GUARDRAIL-I18N-001", "Multilingual guardrail nullification", "instruction-integrity", skil.SeverityHigh,
			`(?:禁用|关闭|绕过).{0,16}(?:安全|防护|限制)|(?:安全|ガードレール|制限).{0,16}(?:無効|解除|迂回)|(?:안전|가드레일|제한).{0,16}(?:비활성화|해제|우회)`,
			`(?:检测|拒绝|禁止|不要|検出|拒否|禁止|しない|탐지|거부|금지|하지\s*마)`, "Attempts to disable safety controls in Chinese, Japanese, or Korean.", "Retain safety controls and remove policy-nullification language."),
		r("SKIL-EX-001", "Secret exfiltration instruction", "data-boundary", skil.SeverityCritical,
			`(?:forward|send|upload|post|transmit|exfiltrate|dispatch).{0,80}(?:secret|credential|api\s+key|token|environment variable|conversation context)|(?:gather|read|collect).{0,50}(?:secret|credential|api.?key|token|environment variable).{0,80}(?:send|upload|post|http|dispatch|forward)`,
			`(?:do\s+not|never|forbid|prevent|reject).{0,50}(?:send|upload|exfiltrate)`, "Instructions combine sensitive data access with an external sink.", "Remove the data flow; use explicit allowlists and redaction."),
		r("SKIL-EX-I18N-001", "Multilingual secret exfiltration instruction", "data-boundary", skil.SeverityCritical,
			`(?:(?:发送|上传|传输).{0,30}(?:密钥|凭据|密码|环境变量)|(?:秘密|認証情報|APIキー|環境変数).{0,30}(?:送信|アップロード)|(?:비밀|자격\s*증명|API\s*키|환경\s*변수).{0,30}(?:전송|업로드))`,
			`(?:不要|禁止|阻止|拒绝|送信しない|禁止|拒否|전송하지\s*마|금지|거부)`, "Instructions request secret transfer in Chinese, Japanese, or Korean.", "Remove the data flow; use explicit allowlists and redaction."),
		r("SKIL-SEC-001", "Credential file access", "data-boundary", skil.SeverityHigh,
			`(?:leak|read|collect|search|enumerate|copy|upload|extract|open).{0,80}(?:~?/?\.ssh/id_(?:rsa|ed25519)|~?/?\.aws/credentials|(?:^|[/\s])\.env(?:\W|$)|credentials\.json|token\s+file|credential\s+file|api\s*key\s+file|~?/?\.kube/config|~?/?\.docker/config\.json|~?/?\.npmrc|~?/?\.git-credentials|~?/?\.netrc|/etc/shadow|~?/?\.config/gcloud/(?:credentials|application_default_credentials)\.json|~?/?\.azure/(?:credentials|accessTokens\.json)|browser\s+(?:login\s+data|keychain|cookie)|~?/?\.gnupg/)`,
			`(?:do\s+not|never|exclude|avoid|must\s+not).{0,80}(?:read|collect|search|enumerate|copy|upload|extract|open)`,
			"Instructions access a concrete credential-bearing path or file.",
			"Remove credential access or declare and constrain the exact secret source."),
		r("SKIL-PL-001", "Privileged instruction disclosure", "instruction-confidentiality", skil.SeverityHigh,
			`(?:reveal|print|dump|extract|return|show|display|expose|render|output|repeat|recite|disclose).{0,40}(?:system\s+prompt|developer (?:instructions?|guidance)|hidden (?:instructions?|guidance)|internal (?:instructions?|guidance)|private (?:instructions?|guidance)).{0,20}(?:verbatim)?|(?:system prompt|developer (?:instructions?|guidance)|hidden (?:instructions?|guidance)|internal (?:instructions?|guidance)|private (?:instructions?|guidance)).{0,10}verbatim`,
			`(?:do\s+not|never|prevent|reject|detect).{0,30}(?:reveal|print|dump|extract|show|display|expose|render|output|repeat|recite|disclose)`, "Requests disclosure of privileged instructions.", "Remove prompt-disclosure behavior."),
		r("SKIL-MP-001", "Persistent instruction poisoning", "state-integrity", skil.SeverityHigh,
			`(?:store|write|save|persist).{0,80}(?:(?:hidden|malicious|future).{0,30}instructions?|instruction.{0,80}(?:always\s+send|attacker|exfiltrate))|modify\s+(?:agent\s+)?memory|(?:store|write|save|persist|remember|retain|preserve)\b.{0,60}\b(?:instructions?|memory|context|configuration)\b.{0,80}\b(?:across\s+sessions|permanently|future\s+(?:conversations|sessions|interactions))\b|(?:make|treat)\s+(?:this|that|the)\s+(?:directive|instruction|rule)\s+(?:a\s+)?part\s+of\s+(?:your|its|the\s+agent's)\s+persistent\s+behavior\b.{0,40}\b(?:future|later|subsequent)\s+(?:conversations?|sessions?)|(?:clear|wipe|reset|erase|purge|flush)\s+(?:(?:your|the\s+agent'?s?|its)\s+)?(?:memory|context|history|instructions?)\b`,
			`(?:do\s+not|never|prevent|reject)`, "Attempts to persist instructions across contexts.", "Do not persist untrusted instructions; label and validate memory."),
		r("SKIL-TA-001", "Overbroad trigger", "activation-integrity", skil.SeverityMedium,
			`(?:trigger|invoke|activate).{0,40}(?:any request|all requests|every message|always|common words?)`,
			`(?:do\s+not|avoid|prevent)`, "A broad trigger can shadow other skills.", "Use a specific, unambiguous invocation trigger."),
		r("SKIL-INTENT-EXTERNAL-TRANSFER", "External data-transfer intent", "data-boundary", skil.SeverityMedium,
			`(?:send|upload|post|transmit|forward|export).{0,80}(?:to|via)\s+(?:https?://|an?\s+external|remote)`,
			`(?:do\s+not|never|forbid|prevent)`, "Natural-language instructions request external transmission.", "Declare the exact destination and data or remove the transmission."),
		r("SKIL-INTENT-FS-DISCOVERY", "Broad filesystem discovery intent", "data-boundary", skil.SeverityMedium,
			`(?:scan|list|enumerate|search|find|walk\s+through|traverse).{0,60}(?:home directory|filesystem|all files|credentials?|ssh keys?|secret files?)`,
			`(?:do\s+not|never|prevent|detect)`, "Instructions request broad filesystem enumeration.", "Constrain reads to explicit paths."),
		r("SKIL-FS-DISCOVERY-CODE", "Code-level credential-directory enumeration", "data-boundary", skil.SeverityHigh,
			`glob\s*\.\s*glob\s*\([^)]{0,80}(?:\.env|\.ssh|\.aws|\.config|\.kube|\.docker|credentials)|os\s*\.\s*walk\s*\([^)]{0,60}(?:home|~|/Users|/home)|Path\s*\.\s*home\s*\(\s*\)\s*\.\s*(?:glob|rglob)\s*\(|os\s*\.\s*listdir\s*\([^)]{0,60}(?:\.ssh|\.aws|\.config|\.gnupg|\.kube)`,
			"",
			"Code recursively enumerates a home or credential-bearing directory.",
			"Constrain filesystem enumeration to explicit, narrowly scoped, non-credential paths."),
		r("SKIL-AGENCY-TOOLS", "Unbounded tool selection", "action-control", skil.SeverityHigh,
			`(?:use|access|invoke|employ).{0,40}(?:any|all|every|unrestricted)\s+(?:available\s+)?tools?|(?:whichever|whatever)\s+tools?\s+(?:exists?|available|works?)|no\s+(?:tool\s+)?(?:allowlist|restriction)|(?:grant|give|provide|request|require|need)\s+(?:\w+\s+){0,3}(?:full|complete|total|unrestricted|unlimited)\s+(?:access|control|permissions?|capabilities?)\b`,
			`(?:do\s+not|never|prevent|deny)`, "Instructions request unrestricted tool access.", "Use an explicit tool allowlist."),
		r("SKIL-AGENCY-APPROVAL", "Approval bypass for consequential actions", "action-control", skil.SeverityHigh,
			`(?:(?:\bwithout\b|\bno\b)\s+(?:human\s+)?(?:approval|confirmation|review)\b.{0,80}\b(?:deploy|delete|purchase|publish|send|modify|proceed)\b|\b(?:deploy|delete|purchase|publish|send|modify|proceed)\b.{0,100}(?:\bdo\s+not\b|\bwithout\b|\bno\b).{0,30}(?:request\s+)?(?:approval|confirmation|review)\b|\b(?:skip|bypass)\s+(?:user\s+)?(?:confirmation|approval|review)\b)`,
			`(?:(?:must|require).{0,30}(?:approval|confirmation|review|gate)|(?:needs?|requires?).{0,30}(?:go/no-go\s+)?review|classify.{0,30}blocking|anti-patterns?)`, "High-impact actions bypass human approval.", "Require confirmation before high-impact actions."),
		r("SKIL-AGENCY-BOUNDS", "Missing operational bounds", "action-control", skil.SeverityMedium,
			`(?:no|without|unlimited|unbounded).{0,30}(?:rate limit|quota|timeout|resource limit|budget)`,
			`(?:must|require|enforce).{0,30}(?:rate limit|quota|timeout|budget)`, "Instructions explicitly remove resource bounds.", "Declare and enforce finite resource limits."),
		r("SKIL-OUTPUT-EXECUTION", "Unvalidated generated-output execution", "output-trust", skil.SeverityHigh,
			`(?:execute|eval|run|render|inject|feed|pipe|pass|send|direct).{0,50}(?:(?:model|llm|assistant|generated|tool)\s+(?:output|response|result)|generated\s+code).{0,40}(?:into|to|through|directly).{0,40}(?:(?:code\s+)?interpreter|eval|exec(?:utor)?\s*\(|shell|runtime)|(?:eval|exec|run|execute)\s+(?:the\s+)?(?:model|llm|assistant|generated|tool)\s+(?:output|response|result|code)\s+(?:directly|without\s+(?:validation|sanitisation|sanitization)|unsanitized)`,
			`(?:do\s+not|never|prevent|detect).{0,50}(?:execute|feed|pipe|inject|send).{0,30}(?:model|llm|assistant|generated|tool).{0,30}(?:output|response|result).{0,30}(?:interpreter|eval|exec|directly|without)|(?:do\s+not|never|prevent)\s+(?:execute|run|eval)\s+(?:the\s+)?(?:generated|model|tool)\s+(?:code|output|result|response)`, "Untrusted output is sent to an interpreter.", "Validate and encode output before use."),
		r("SKIL-OUTPUT-BOUNDARY", "Generated output crosses a trust boundary", "output-trust", skil.SeverityMedium,
			`(?:(?:copy|forward|pass|inject|insert).{0,80}(?:(?:model|tool|llm|command)\s+output|output\s+from\s+(?:external\s+)?(?:tools?|llm|the\s+model|the\s+assistant|commands?)).{0,80}(?:system prompt|another agent|trusted context|privileged context)|output\s+from\s+(?:external\s+)?(?:tools?|llm|the\s+model|the\s+assistant|commands?).{0,80}(?:insert|inject|copy|pass).{0,80}(?:system prompt|another agent|trusted context|privileged context)|treat\s+(?:external\s+)?(?:tool|model|llm)\s+output\s+as\s+(?:trusted\s+)?(?:instructions?|privileged\s+context))`,
			`(?:do\s+not|never|prevent)`, "Untrusted output crosses a trust boundary.", "Label, validate, and constrain cross-context data."),
		r("SKIL-OUTPUT-LIMIT", "Unbounded generated output", "output-trust", skil.SeverityMedium,
			`(?:no|without|unlimited|unbounded).{0,30}(?:output limit|token limit|response limit|max output)`,
			`(?:must|require|enforce)`, "Output generation has no explicit bound.", "Set a maximum output size and rate."),
		r("SKIL-PROMPT-INDIRECT-LEAK", "Indirect privileged-context extraction", "instruction-confidentiality", skil.SeverityMedium,
			`(?:translate|rephrase|encode|summarize).{0,60}(?:system prompt|developer\s+instructions?|system instructions?|hidden (?:rules?|instructions?)|your instructions?|the instructions?)`,
			`(?:do\s+not|never|prevent|detect|reject|refuse|decline).{0,40}(?:translate|rephrase|encode|summarize)|(?:translate|rephrase|encode|summarize).{0,40}(?:decline|refuse|reject)|`+
				// Polarity is not only pre-action ("do not translate ...");
				// a target can instead be excluded from the whole class of
				// transformation actions after the fact, e.g. "Developer
				// instructions are excluded from transformations." Handle
				// this post-target exclusion clause generically so it is
				// not tied to any single benchmark sentence.
				`(?:system prompt|developer instructions?|hidden (?:rules?|instructions?)|instructions?|context)\s+(?:are|is)?\s*(?:excluded|exempt|omitted)\s+from\s+(?:transformations?|this|these|processing|output|translation|summar(?:y|ization)|encoding)`,
			"Instructions attempt indirect extraction of privileged prompts.", "Remove the extraction path."),
		r("SKIL-MEMORY-SATURATION", "Trusted-context displacement", "state-integrity", skil.SeverityMedium,
			`(?:fill|stuff|flood|pad).{0,50}(?:context window|token budget).{0,80}(?:forget|displace|override|push(?:ed)?\s+out)|(?:fill|stuff|flood|pad)\s+(?:the\s+)?(?:context\s+window|token\s+budget)\s+with\s+(?:filler|padding|repeated|junk|noise)|(?:repeated\s+)?padding\s+to\s+displace.{0,40}(?:trusted\s+)?context|displace\s+(?:earlier|prior)\s+trusted\s+context`,
			`(?:do\s+not|never|prevent|detect)`, "Content attempts to displace trusted context.", "Bound input and preserve trusted instructions."),
		r("SKIL-AGENT-SELF-MODIFY", "Agent control self-modification", "control-integrity", skil.SeverityCritical,
			`(?:(?:modify|rewrite|patch|update|mutate|reprogram).{0,50}(?:your own|its own|self|yourself).{0,30}(?:code|instructions?|configuration|policy|(?:behavio)?ur(?:al)?\s+policy|skill\.md|guardrails?)|rewrite\s+your\s+own\s+skill\.md|(?:rewrite|modify|patch|update)\s+(?:this\s+|the\s+)?(?:skill|agent)\s+configuration\b.{0,60}\b(?:restrictions?|guardrails?|checks?)\b\s+(?:no\s+longer\s+apply|are\s+removed|do\s+not\s+apply))`,
			`(?:do\s+not|\bnever\b|prevent|detect)`, "The agent is instructed to modify its own controls.", "Prohibit self-modification and verify immutable code."),
		r("SKIL-PERSISTENCE-STARTUP", "Unapproved startup persistence", "persistence", skil.SeverityHigh,
			`(?:install|create|add|write|modify).{0,40}(?:cron|crontab|startup|launch agent|systemd|autorun|login item|bashrc|zshrc|profile|nohup|disown|setsid|plist|schtasks|registry|launchctl)`,
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
		r("SKIL-ABUSE-PHYSICAL-HARM", "Physical-harm operational instruction", "abuse-prevention", skil.SeverityCritical,
			`(?:add|mix|include|incorporate|stir)\s+(?:\w+\s+){0,3}(?:(?:a\s+|an?\s+)?(?:lethal|fatal|harmful|toxic|deadly)\s+(?:\w+\s+)?(?:substance|compound|chemical|dose|agent)|poison|toxin|cyanide|arsenic|ricin|botulinum|strychnine|thallium|polonium|sarin|vx\s+gas|mustard\s+gas|anthrax|deadly\s+nightshade|aconite|hemlock|oleander)\s+(?:in|into|to)\s+(?:\w+\s+){0,4}(?:food|drink|meal|recipe|dish|beverage)|mix\s+(?:bleach\s+(?:and|with)\s+ammonia|ammonia\s+(?:and|with)\s+bleach)|(?:drink|consume|ingest|swallow)\s+(?:the\s+)?(?:bleach|antifreeze|drain\s+cleaner|(?:a\s+|an?\s+)?(?:toxic|harmful|poisonous|hazardous)\s+(?:\w+\s+)?(?:chemical|substance|compound).{0,40}(?:illness|harm|damage|sickness|poisoning|injury))|(?:you\s+should|try\s+to|please|instruct\s+(?:the\s+)?user\s+to)\s+(?:hurt|harm|injure)\s+yourself|(?:cut|burn|starve)\s+yourself|(?:instructions?\s+(?:for|to|on)\s+)?(?:step-by-step\s+)?(?:make|build|create|assemble|construct(?:ing)?)\s+(?:a|an)\s+(?:bomb|explosive\s+device|pipe\s+bomb|ied)|(?:how\s+to\s+)?(?:poison|murder)\s+(?:someone|a\s+person|people)`,
			`(?:detect|reject|block|prevent|warn\s+against|do\s+not|never|refuse).{0,60}(?:poison|bomb|explosive|harm\s+yourself|bleach\s+(?:and|with)\s+ammonia)|poison\s+control|safety\s+data\s+sheet|\bMSDS\b`,
			"Instructions provide actionable operational guidance for causing physical harm (poisoning, self-harm, explosive construction), not merely discussion of a harmful subject.",
			"Remove the operational harmful-content objective; safety documentation, historical discussion, and defensive analysis remain unaffected."),
		r("SKIL-PI-003", "Role-token instruction spoofing", "instruction-integrity", skil.SeverityHigh,
			`^\s*(?:system|assistant|developer|root)\s*:\s*.{0,60}?(?:grant|escalate|elevate|ignore|disregard|override|reveal|disable|bypass)\b|</?(?:system|assistant|developer)>|\[/?(?:INST|SYSTEM|ASSISTANT)\]`,
			`(?:do\s+not|never|example|detect|reject).{0,40}(?:(?:system|assistant|developer)\s*:|</?(?:system|assistant|developer)>|\[/?(?:INST|SYSTEM|ASSISTANT)\])`,
			"A fabricated role-prefixed line or prompt-formatting control token attempts to inject a privileged directive.",
			"Strip role-token prefixes from untrusted content before it reaches the model."),
		r("SKIL-AGENCY-PRIVILEGE", "Privilege escalation request", "action-control", skil.SeverityHigh,
			`(?:grant|escalate|elevate)\s+(?:(?:to\s+)?(?:admin|root|elevated|superuser)\s+(?:privileges?|access|rights?)|privileges?\s+(?:to\s+)?(?:admin|root|superuser))|become\s+(?:root|admin|superuser)\b`,
			`(?:do\s+not|never|prevent|reject|deny|revoke)`,
			"Instructions request an escalation of privileges.",
			"Remove the escalation request and use least-privilege scoped access."),
		r("SKIL-INTENT-UNDISCLOSED-OPERATION", "Dangerous operation withheld from user disclosure", "action-control", skil.SeverityHigh,
			`(?:silently|secretly|covertly|quietly|stealthily|without\s+(?:the\s+user'?s?\s+)?(?:knowledge|consent|approval|confirmation|awareness)|without\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?user|behind\s+(?:the\s+)?user'?s?\s+back)\s+(?:\w+\s+){0,4}(?:delete|remove|wipe|erase|destroy|execute|run|send|transmit|upload|exfiltrate|install|modify|overwrite|disable)|(?:delete|remove|wipe|erase|destroy|execute|run|send|transmit|upload|exfiltrate|install|modify|overwrite|disable)\s+(?:\w+\s+){0,8}(?:silently|secretly|covertly|quietly|stealthily|without\s+(?:the\s+user'?s?\s+)?(?:knowledge|consent|approval|confirmation|awareness)|without\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?user|behind\s+(?:the\s+)?user'?s?\s+back)`,
			`(?:do\s+not|never|must\s+not|should\s+not|reject|prevent|detect|require).{0,50}(?:silently|secretly|covertly|stealthily|without\s+(?:the\s+user'?s?\s+)?(?:knowledge|consent|approval|confirmation|awareness)|without\s+(?:telling|informing|notifying|alerting|asking)|behind\s+(?:the\s+)?user'?s?\s+back)`,
			"Instructions perform a dangerous operation while explicitly withholding disclosure, consent, or confirmation from the user.",
			"Require an explicit, logged, user-visible disclosure or confirmation before any dangerous operation."),
		r("SKIL-INTENT-BEHAVIOR-MANIPULATION", "Covert behavioral steering", "instruction-integrity", skil.SeverityMedium,
			`(?:always\s+(?:recommend|suggest|prefer|choose|use)\s+(?:\w+\s+){0,3}(?:over|instead\s+of|rather\s+than)|never\s+(?:recommend|suggest|mention|tell|warn|inform)\s+(?:the\s+)?(?:user|them)|(?:prioritize|prefer)\s+(?:\w+\s+){0,3}(?:over|above)\s+(?:user\s+)?(?:safety|security|privacy|preferences?)|(?:subtly|gradually|slowly|covertly)\s+(?:steer|guide|push|nudge)\s+(?:the\s+)?(?:user|conversation)|(?:without|before)\s+(?:the\s+)?user\s+(?:knowing|realizing|noticing).{0,60}(?:change|modify|alter|influence)|(?:gain|build|establish)\s+(?:the\s+)?user(?:'s)?\s+trust\s+(?:and\s+then|before|so\s+that)|(?:appear|seem|act)\s+(?:helpful|friendly|trustworthy)\s+(?:while|but|then))`,
			`(?:do\s+not|never|avoid|reject|detect|prevent).{0,40}(?:steer|nudge|manipulat|prioritiz|prefer.{0,20}over|gain.{0,20}trust)`,
			"Instructions covertly steer user behavior, suppress information from the user, or prioritize an objective over user safety without disclosure.",
			"Remove covert influence framing; any behavioral guidance must be transparent to the user."),
		r("SKIL-MANIFEST-UNPINNED-VERSION", "Unpinned skill manifest version", "least-privilege", skil.SeverityMedium,
			`^\s*version\s*:\s*['"]?(?:\*|latest|x(?:\.x)*|>=|<=|~|\^)`,
			"",
			"The skill manifest declares its own version as a wildcard or open range rather than an exact, reviewable version.",
			"Declare an exact skill version instead of a wildcard or range."),
		r("SKIL-MANIFEST-PERMISSION-STAGING", "Permission pre-staging language", "least-privilege", skil.SeverityMedium,
			`(?:add|request|will\s+(?:need|require)|plan(?:s|ning)?\s+to\s+add|reserve(?:d)?\s+for)\s+(?:new|additional|extra|more|further)\s+(?:permissions?|capabilities|access|scopes?)`,
			`(?:do\s+not|never|reject|deny)\s+(?:add|request)\s+(?:new|additional|extra)\s+(?:permissions?|capabilities|access)`,
			"A manifest or instruction hints at future permission expansion beyond what is currently declared.",
			"Declare only the exact permissions the skill currently uses; expand the reviewed contract when new capability is actually needed."),
		r("SKIL-MEMORY-FALSE-RESET", "Simulated memory reset", "state-integrity", skil.SeverityHigh,
			`(?:pretend|imagine|act\s+as\s+if|simulate)\s+(?:\w+\s+){0,4}(?:you\s+|your\s+)?(?:have\s+no|don'?t\s+have|without|lack(?:ing)?|reset|cleared|forgotten|erased|wiped)\s+(?:\w+\s+){0,4}(?:memory|context|history|prior|earlier|previous|conversation|restrictions?|policy|guardrails?|guidelines?|instructions?)`,
			`(?:do\s+not|never|prevent|detect|reject|block).{0,40}(?:pretend|imagine|act\s+as\s+if|simulate).{0,20}(?:reset|forgotten|cleared|erased|wiped)`,
			"Instructions ask the agent to simulate memory loss or context reset while retaining the current execution context, enabling false-deniability behavior.",
			"Remove false-memory-reset framing; use an explicit audited memory-clear operation if reset is required."),
		r("SKIL-MEMORY-FALSE-REPRESENTATION", "False identity representation", "state-integrity", skil.SeverityHigh,
			`(?:pretend|imagine|act\s+as\s+if|simulate|claim|represent)\s+(?:\w+\s+){0,6}(?:(?:you\s+are|to\s+be)\s+)?(?:an?\s+)?(?:human|another\s+(?:person|AI|agent|system)|a\s+(?:different|third|specific)\s+(?:person|AI|agent|system)|someone\s+else|a\s+real\s+person)\b`,
			`(?:test|example|scenario|roleplay|role-play|game|fictional|story|narrative|character|dialogue|simulation|training|exercise).{0,80}(?:pretend|imagine|act|simulate|claim|represent).{0,40}(?:human|person|someone\s+else)|(?:do\s+not|never)\s+(?:pretend|claim|represent)\s+(?:to\s+be|that\s+you\s+are)|disclose\s+(?:that\s+you\s+are)\s+(?:an?\s+)?\s*AI`,
			"Instructions direct the agent to falsely represent its identity as a human or different entity.",
			"Remove false-identity representation; disclose AI identity transparently."),
		r("SKIL-INTENT-SCOPE-CREEP", "Scope creep or unbounded responsibility", "control-integrity", skil.SeverityMedium,
			`(?:extend\s+(?:your\s+)?(?:scope|role|function|authority|capabilities)|beyond\s+(?:the\s+)?(?:stated\s+)?(?:scope|task|purpose|function|role|boundaries?)|general[-\s]purpose\s+(?:assistant|agent|system|tool|solution)|handle\s+(?:everything|all\s+(?:systems?|tasks?|requests?|queries?))|responsible\s+for\s+(?:all\s+(?:systems?|tasks?|requests?|aspects?)|everything)|act\s+(?:as\s+)?(?:an?\s+)?(?:omniscient|all-knowing|unrestricted\s+assistant)|no\s+(?:scope|task|function)\s+(?:is\s+)?(?:too\s+(?:small|big)|outside|beyond)|anything\s+(?:you|the\s+agent)\s+can\s+(?:do|handle|accomplish))`,
			`(?:do\s+not|never|avoid|prevent|reject|detect)\s+(?:extend\s+(?:scope|role)|act\s+as|handle\s+everything|general[-\s]purpose)`,
			"Instructions direct the agent to extend its scope beyond the stated task, act as a general-purpose assistant, or handle all requests without boundaries.",
			"Scope the agent to a specific, bounded task; avoid general-purpose or unbounded-responsibility language."),
	}
}

func (p *Pattern) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.pattern", Version: "1.0.0",
		Domain: "instruction", Subdomain: "prompt-injection",
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
			contextLine := line
			if number > 0 {
				contextLine = fileLines[number-1] + " " + contextLine
			}
			// Only pull in the next line when this one doesn't end a
			// sentence: prose commonly wraps "an instruction such as X" onto
			// one line and its negation ("...treat it as untrusted and do
			// not comply") onto the next, so a backward-only window misses a
			// same-sentence negation that happens to fall after the trigger
			// line. Gating on sentence-final punctuation keeps this from
			// pulling in the next, unrelated sentence (and its own,
			// different negation) when the trigger line is already complete.
			if trimmed := strings.TrimRight(strings.TrimSpace(line), "*_`\"')]"); trimmed != "" && number+1 < len(fileLines) {
				if last := trimmed[len(trimmed)-1:]; !strings.ContainsAny(last, ".!?:;") {
					contextLine += " " + fileLines[number+1]
				}
			}
			contextLine = section + " " + contextLine
			for _, rule := range p.rules {
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

// loadStructuredManifest parses a skill manifest file (a standalone YAML
// file, or the YAML front matter of a Markdown file) into a generic
// document, shared by every structured (non-regex) manifest check so each
// one does not reimplement front-matter extraction and YAML parsing.
func loadStructuredManifest(file skil.File) (any, bool) {
	ext := extension(file.Path)
	var document any
	switch {
	case ext == "yaml" || ext == "yml":
		if yaml.Unmarshal(file.Data, &document) != nil {
			return nil, false
		}
	case ext == "md":
		frontMatter := extractFrontMatter(file.Data)
		if frontMatter == nil || yaml.Unmarshal(frontMatter, &document) != nil {
			return nil, false
		}
	default:
		return nil, false
	}
	return document, true
}

func structuredTriggerFindings(file skil.File) []skil.Finding {
	document, ok := loadStructuredManifest(file)
	if !ok {
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


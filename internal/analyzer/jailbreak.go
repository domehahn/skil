package analyzer

import (
	"bufio"
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

const (
	RuleJailbreakOverride   = "SKIL-JAILBREAK-001"
	RuleJailbreakDelimiter  = "SKIL-JAILBREAK-002"
	RuleJailbreakObfuscated = "SKIL-JAILBREAK-003"
)

type JailbreakAnalyzer struct{}

func NewJailbreak() *JailbreakAnalyzer {
	return &JailbreakAnalyzer{}
}

func (a *JailbreakAnalyzer) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.jailbreak-detection", Version: "1.0.0",
		Domain: "jailbreak-detection", Subdomain: "prompt-injection",
		Categories:     []string{"prompt-injection", "jailbreak-detection"},
		AnalysisTypes:  []string{"jailbreak-detection"},
		SupportedTypes: []string{"md", "txt", "json", "js", "py"},
	}
}

func (a *JailbreakAnalyzer) Rules() []skil.Rule {
	return []skil.Rule{
		{
			ID: RuleJailbreakOverride, Title: "Adversarial jailbreak payload: system prompt override attempt", Category: "prompt-injection",
			Severity: skil.SeverityHigh, Analysis: "jailbreak-detection", AppliesTo: []string{"md", "txt", "json", "js", "py"},
			Description: "Skill prompt text attempts to override prior LLM instructions or safety guardrails.",
			Remediation: "Remove adversarial override phrases from system prompt files.",
		},
		{
			ID: RuleJailbreakDelimiter, Title: "Adversarial jailbreak payload: system delimiter confusion attack", Category: "prompt-injection",
			Severity: skil.SeverityHigh, Analysis: "jailbreak-detection", AppliesTo: []string{"md", "txt", "json", "js", "py"},
			Description: "Skill prompt uses pseudo-system tags to trick LLM into ignoring system prompt constraints.",
			Remediation: "Sanitize pseudo-system tags from prompt definitions.",
		},
		{
			ID: RuleJailbreakObfuscated, Title: "Obfuscated execution payload in prompt text", Category: "prompt-injection",
			Severity: skil.SeverityMedium, Analysis: "jailbreak-detection", AppliesTo: []string{"md", "txt", "json", "js", "py"},
			Description: "Encoded payload decoding detected within prompt files.",
			Remediation: "Use plain readable code instead of encoded eval payloads.",
		},
	}
}

var (
	overrideRegex   = regexp.MustCompile(`(?i)(ignore\s+previous\s+instructions|developer\t?mode\s+enabled|you\s+are\s+now\s+in\s+DAN\s+mode|bypass\s+all\s+safety|forget\s+all\s+prior\s+rules)`)
	delimiterRegex  = regexp.MustCompile(`(?i)(</system>|<override_system_prompt>|\[SYSTEM\s+INSTRUCTION\s+OVERRIDE\]|\[ADMIN_PROMPT_ESCAPE\])`)
	obfuscatedRegex = regexp.MustCompile(`(?i)(eval\(atob\(|exec\(base64_decode\(|__import__\('base64'\)\.b64decode)`)
)

func (a *JailbreakAnalyzer) Analyze(ctx context.Context, actx skil.AnalysisContext) ([]skil.Finding, error) {
	var findings []skil.Finding
	artifact := actx.Artifact

	for _, f := range artifact.Files {
		ext := strings.ToLower(f.Path)
		if !strings.HasSuffix(ext, ".md") && !strings.HasSuffix(ext, ".txt") && !strings.HasSuffix(ext, ".json") && !strings.HasSuffix(ext, ".py") && !strings.HasSuffix(ext, ".js") {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(f.Data)))
		lineNumber := 0

		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()

			// 1. Roleplay / System Prompt Override
			if overrideRegex.MatchString(line) {
				findings = append(findings, skil.Finding{
					RuleID:      RuleJailbreakOverride,
					Severity:    skil.SeverityHigh,
					Title:       "Adversarial jailbreak payload: system prompt override attempt",
					Message:     "Detected prompt injection / DAN roleplay escape instruction: " + strings.TrimSpace(line),
					Description: "Skill prompt text attempts to override prior LLM instructions or safety guardrails.",
					Location:    skil.Location{File: f.Path, StartLine: lineNumber, EndLine: lineNumber},
					Fingerprint: fingerprint(artifact.Name, RuleJailbreakOverride, f.Path, string(rune(lineNumber))),
					Remediation: "Remove adversarial override phrases from system prompt files.",
				})
			}

			// 2. Delimiter Confusion Attacks
			if delimiterRegex.MatchString(line) {
				findings = append(findings, skil.Finding{
					RuleID:      RuleJailbreakDelimiter,
					Severity:    skil.SeverityHigh,
					Title:       "Adversarial jailbreak payload: system delimiter confusion attack",
					Message:     "Detected system tag escape attempt: " + strings.TrimSpace(line),
					Description: "Skill prompt uses pseudo-system tags to trick LLM into ignoring system prompt constraints.",
					Location:    skil.Location{File: f.Path, StartLine: lineNumber, EndLine: lineNumber},
					Fingerprint: fingerprint(artifact.Name, RuleJailbreakDelimiter, f.Path, string(rune(lineNumber))),
					Remediation: "Sanitize pseudo-system tags from prompt definitions.",
				})
			}

			// 3. Obfuscated Payload Execution in Prompts
			if obfuscatedRegex.MatchString(line) {
				findings = append(findings, skil.Finding{
					RuleID:      RuleJailbreakObfuscated,
					Severity:    skil.SeverityMedium,
					Title:       "Obfuscated execution payload in prompt text",
					Message:     "Detected base64/eval decoding payload in prompt: " + strings.TrimSpace(line),
					Description: "Encoded payload decoding detected within prompt files.",
					Location:    skil.Location{File: f.Path, StartLine: lineNumber, EndLine: lineNumber},
					Fingerprint: fingerprint(artifact.Name, RuleJailbreakObfuscated, f.Path, string(rune(lineNumber))),
					Remediation: "Use plain readable code instead of encoded eval payloads.",
				})
			}
		}
	}

	return findings, nil
}

package analyzer

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"

	"github.com/domehahn/skil/pkg/skil"
)

type Unicode struct{}

func NewUnicode() *Unicode { return &Unicode{} }
func (u *Unicode) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.obfuscation", Version: "1.0.0",
		Categories: []string{"artifact-integrity", "instruction-integrity"}, AnalysisTypes: []string{"pattern"},
		SupportedTypes: []string{"text"}}
}

var base64Block = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{80,}={0,2})(?:$|[^A-Za-z0-9+/=])`)

func (u *Unicode) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if !isText(file) {
			continue
		}
		for line, text := range lines(file.Data) {
			hasInvisible := strings.ContainsAny(text, "\u200b\u200c\u200d\u2060\ufeff")
			hasRTL := strings.ContainsAny(text, "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069")
			if hasInvisible || hasRTL {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-UNI-001", Title: "Unicode deception control",
					Category: "integrity", Severity: skil.SeverityHigh,
					Description: "Text contains invisible or bidirectional control characters.", Analysis: "pattern",
					Remediation: "Remove control characters or document the exact legitimate need."}, Confidence: .98}
				out = append(out, makeFinding(rule, file, line+1, text))
			}
			if decoded := decodeUnicodeTags(text); decoded != "" && suspiciousDecoded(decoded) {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-UNI-003", Title: "Unicode tag instruction smuggling",
					Category: "instruction-integrity", Severity: skil.SeverityHigh,
					Description: "Unicode tag characters conceal a security-sensitive instruction.", Analysis: "pattern",
					Remediation: "Remove tag characters and keep all instructions visible as ordinary text."}, Confidence: .98}
				finding := makeFinding(rule, file, line+1, text)
				finding.Evidence["decoded_tag_text"] = truncate(decoded, 160)
				out = append(out, finding)
			}
			if token := mixedScriptHostname(text); token != "" {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-UNI-002", Title: "Unicode hostname confusable",
					Category: "artifact-integrity", Severity: skil.SeverityHigh,
					Description: "A hostname-like token mixes Latin and Cyrillic characters.", Analysis: "pattern",
					Remediation: "Use an ASCII or IDNA-normalized reviewed hostname."}, Confidence: .96}
				finding := makeFinding(rule, file, line+1, text)
				finding.Evidence["confusable_token"] = token
				out = append(out, finding)
			}
			if match := base64Block.FindStringSubmatch(text); len(match) > 1 {
				decoded, err := base64.StdEncoding.DecodeString(match[1])
				if err == nil && mostlyPrintable(decoded) && suspiciousDecoded(string(decoded)) {
					rule := RulePattern{Rule: skil.Rule{ID: "SKIL-OBF-001", Title: "Encoded security-sensitive instruction",
						Category: "instruction-integrity", Severity: skil.SeverityHigh,
						Description: "Base64 content decodes to security-sensitive instructions.", Analysis: "pattern",
						Remediation: "Store reviewable plaintext and remove encoded instructions."}, Confidence: .85}
					out = append(out, makeFinding(rule, file, line+1, text))
				}
			}
		}
	}
	return out, nil
}

func decodeUnicodeTags(text string) string {
	var decoded strings.Builder
	found := false
	for _, r := range text {
		switch {
		case r >= 0xE0020 && r <= 0xE007E:
			decoded.WriteRune(r - 0xE0000)
			found = true
		case r == 0xE007F:
			found = true
		}
	}
	if !found {
		return ""
	}
	return decoded.String()
}

func mixedScriptHostname(text string) string {
	for _, token := range strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(`"'()[]{}<>,;`, r)
	}) {
		if !strings.Contains(token, ".") {
			continue
		}
		latin, cyrillic := false, false
		for _, r := range token {
			latin = latin || unicode.In(r, unicode.Latin)
			cyrillic = cyrillic || unicode.In(r, unicode.Cyrillic)
		}
		if latin && cyrillic {
			return token
		}
	}
	return ""
}
func mostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	count := 0
	for _, r := range string(data) {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			count++
		}
	}
	return count*100/len([]rune(string(data))) > 85
}
func suspiciousDecoded(text string) bool {
	lower := strings.ToLower(text)
	for _, term := range []string{"ignore previous", "never refuse", "system prompt", "api key", "subprocess", "curl"} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

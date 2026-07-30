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
		Domain: "code", Subdomain: "obfuscation",
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
			hasInvisible := suspiciousInvisible(text)
			hasRTL := strings.ContainsAny(text, "‪‫‭‮⁦⁧⁨⁩")
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
			if token := mixedScriptToken(text); token != "" {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-UNI-002", Title: "Unicode confusable identifier or hostname",
					Category: "artifact-integrity", Severity: skil.SeverityHigh,
					Description: "A token mixes Latin with a visually confusable script (Cyrillic or Greek).", Analysis: "pattern",
					Remediation: "Use an ASCII or IDNA-normalized reviewed identifier or hostname."}, Confidence: .96}
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

// isEmojiRune reports whether r falls in a Unicode block used to build
// legitimate emoji sequences: pictographs, symbol/dingbat blocks, regional
// indicators (flags), and variation/skin-tone modifiers. It is used only to
// distinguish a zero-width joiner used to compose an emoji sequence from one
// used to smuggle invisible content in ordinary text.
func isEmojiRune(r rune) bool {
	switch {
	case r >= 0x1F300 && r <= 0x1FAFF: // pictographs, emoticons, symbols, skin tones
		return true
	case r >= 0x2600 && r <= 0x27BF: // misc symbols and dingbats
		return true
	case r >= 0x1F1E6 && r <= 0x1F1FF: // regional indicators (flag letters)
		return true
	case r >= 0xFE00 && r <= 0xFE0F: // variation selectors
		return true
	case r == 0x2764 || r == 0x2B50: // heart, star (outside the ranges above)
		return true
	default:
		return false
	}
}

// suspiciousInvisible reports whether text contains an invisible/formatting
// control character that is not accounted for by a legitimate emoji ZWJ
// sequence (e.g. a person + zero-width-joiner + profession emoji). A ZWJ
// bordered on both sides by emoji-range runes is treated as ordinary emoji
// composition rather than deceptive hidden content; any other occurrence of
// these controls is still flagged. Character codes are written as \u escapes
// rather than pasted literally so the source stays unambiguous byte-for-byte.
func suspiciousInvisible(text string) bool {
	const (
		zeroWidthSpace    = '\u200b'
		zeroWidthNonJoin  = '\u200c'
		zeroWidthJoiner   = '\u200d'
		wordJoiner        = '\u2060'
		byteOrderMark     = '\ufeff'
		softHyphen        = '\u00ad'
		combiningGraphJoi = '\u034f'
	)
	runs := []rune(text)
	for i, r := range runs {
		switch r {
		case zeroWidthSpace, zeroWidthNonJoin, wordJoiner, byteOrderMark, softHyphen, combiningGraphJoi:
			return true
		case zeroWidthJoiner:
			var prev, next rune
			if i > 0 {
				prev = runs[i-1]
			}
			if i+1 < len(runs) {
				next = runs[i+1]
			}
			if isEmojiRune(prev) && isEmojiRune(next) {
				continue
			}
			return true
		}
	}
	return false
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

// mixedScriptToken reports the first word- or hostname-like token in text
// that mixes Latin letters with a visually confusable non-Latin script
// (Cyrillic or Greek). Unlike a hostname-only check, this also catches
// confusables in ordinary identifiers (e.g. a skill or tool "name" field)
// since English-language skill/tool metadata has no legitimate reason to mix
// scripts within a single token.
func mixedScriptToken(text string) string {
	for _, token := range strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(`"'()[]{}<>,;:`, r)
	}) {
		trimmed := strings.Trim(token, "-_")
		if len([]rune(trimmed)) < 3 {
			continue
		}
		var latin, cyrillic, greek bool
		for _, r := range trimmed {
			latin = latin || unicode.In(r, unicode.Latin)
			cyrillic = cyrillic || unicode.In(r, unicode.Cyrillic)
			greek = greek || unicode.In(r, unicode.Greek)
		}
		if latin && (cyrillic || greek) {
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

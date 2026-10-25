package skil

import "strings"

// SeverityUnknown marks an external or malformed severity label that could not
// be mapped. It is deliberately ranked conservatively (see SeverityRank) so an
// unrecognised label can never silently become LOW or INFO.
const SeverityUnknown Severity = "UNKNOWN"

// SeverityNormalization preserves the original label as provenance next to the
// canonical value.
type SeverityNormalization struct {
	Canonical Severity `json:"canonical"`
	Original  string   `json:"original"`
	Known     bool     `json:"known"`
}

// NormalizeSeverity maps a label to the canonical severity. Unrecognised and
// empty labels yield SeverityUnknown with Known=false.
func NormalizeSeverity(label string) SeverityNormalization {
	switch s := Severity(strings.ToUpper(strings.TrimSpace(label))); s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return SeverityNormalization{Canonical: s, Original: label, Known: true}
	}
	return SeverityNormalization{Canonical: SeverityUnknown, Original: label}
}

// SeverityRank is the single canonical ordering used by analyzers, policy,
// reports, closure and trust. Unknown severities rank as HIGH (3): high enough
// that a "fail on high" gate trips, but not claiming certainty of CRITICAL.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo, "":
		// "" means no severity recorded (e.g. no maximum yet); it is not an
		// unrecognised label. Labels go through NormalizeSeverity first.
		return 0
	default:
		return 3
	}
}

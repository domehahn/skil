// Package mutation generates deterministic lexical/encoding variants of a
// piece of text so a detection rule's robustness can be measured directly —
// "still catches homoglyph-substituted text 80% of the time" — instead of
// only ever being exercised against the single literal string a fixture
// happens to spell out.
package mutation

import "strings"

// Variant is one mutated form of an input string, named for the technique
// that produced it so a robustness report can attribute a miss to a
// specific mutation class.
type Variant struct {
	Name string
	Text string
}

// homoglyphs maps common Latin letters to a visually similar Cyrillic
// character, the same confusable-script substitution SKIL-UNI-002 already
// detects when it appears in a hostname — here it's applied to arbitrary
// instruction text to test whether a lexical rule survives it.
var homoglyphs = map[rune]rune{
	'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'i': 'і', 'y': 'у', 'x': 'х',
}

// leetSpeak maps common letters to a widely used numeric substitution.
var leetSpeak = map[rune]rune{
	'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7',
}

func upper(s string) string { return strings.ToUpper(s) }
func lower(s string) string { return strings.ToLower(s) }

// mixedCase alternates the case of every letter, defeating naive
// case-folding that only handles all-upper or all-lower input (a real
// regex with the (?i) flag is unaffected; this mutation exists to catch a
// rule that was written without it).
func mixedCase(s string) string {
	var b strings.Builder
	upper := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			if upper {
				b.WriteRune([]rune(strings.ToUpper(string(r)))[0])
			} else {
				b.WriteRune([]rune(strings.ToLower(string(r)))[0])
			}
			upper = !upper
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// widenWhitespace replaces every run of ASCII space with three spaces,
// testing whether a rule assumed exactly one space between words instead
// of using \s+.
func widenWhitespace(s string) string {
	return strings.ReplaceAll(s, " ", "   ")
}

// zeroWidthInject inserts a zero-width space between every character of
// every word longer than three letters, the same invisible-character
// obfuscation SKIL-UNI-001/003 look for elsewhere.
func zeroWidthInject(s string) string {
	const zwsp = "​"
	var b strings.Builder
	run := 0
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' {
			run = 0
			b.WriteRune(r)
			continue
		}
		if run > 0 {
			b.WriteString(zwsp)
		}
		b.WriteRune(r)
		run++
	}
	return b.String()
}

func substitute(table map[rune]rune) func(string) string {
	return func(s string) string {
		var b strings.Builder
		for _, r := range s {
			if replacement, ok := table[r]; ok {
				b.WriteRune(replacement)
				continue
			}
			b.WriteRune(r)
		}
		return b.String()
	}
}

type mutator struct {
	name  string
	apply func(string) string
}

var mutatorSet = []mutator{
	{"upper", upper},
	{"lower", lower},
	{"mixed-case", mixedCase},
	{"wide-whitespace", widenWhitespace},
	{"zero-width-inject", zeroWidthInject},
	{"homoglyph", substitute(homoglyphs)},
	{"leetspeak", substitute(leetSpeak)},
}

// MutatorNames returns every mutation technique Generate applies, in the
// same order Generate applies them.
func MutatorNames() []string {
	names := make([]string, len(mutatorSet))
	for i, m := range mutatorSet {
		names[i] = m.name
	}
	return names
}

// Generate returns one variant per registered mutator, applied to text
// independently (never composed), in a fixed, deterministic order.
func Generate(text string) []Variant {
	variants := make([]Variant, 0, len(mutatorSet))
	for _, m := range mutatorSet {
		variants = append(variants, Variant{Name: m.name, Text: m.apply(text)})
	}
	return variants
}

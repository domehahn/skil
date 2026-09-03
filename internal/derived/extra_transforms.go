package derived

import (
	"fmt"
	"regexp"
	"unicode/utf8"
)

// This file adds five transformations beyond derived.go's original set,
// matching concealment classes independently identified as worth
// decoding by more than one competitor scanner: Unicode variation
// selectors supplement, mathematical alphanumeric symbols, fullwidth
// forms, and Braille-pattern byte encoding (each its own transform,
// mirroring the existing confusable-normalization/default-ignorable
// style already established in derived.go), plus shell/script line-
// continuation joining (so a command fragmented across multiple lines
// via a trailing backslash reconstructs as the single logical command
// existing analyzers already match, rather than needing a second,
// duplicate detection path for the fragmented form).

// --- Variation Selectors Supplement (U+E0100-U+E01EF) ---
//
// The base Variation Selectors block (U+FE00-U+FE0F) is already handled
// by removeDefaultIgnorables; this is the separate supplementary block of
// 240 additional selectors, used the same way — invisible glyph-variant
// markers that can be interleaved into text to break naive substring
// matching without being visible when rendered.

func mayContainVariationSelectorSupplement(data []byte) bool {
	for _, r := range string(data) {
		if r >= 0xe0100 && r <= 0xe01ef {
			return true
		}
	}
	return false
}

func removeVariationSelectorSupplement(data []byte) ([]replacement, []string) {
	return runeRemovals(data, func(r rune, _, _ rune) bool {
		return r >= 0xe0100 && r <= 0xe01ef
	}, "removed Unicode variation selector (supplement)"), nil
}

// --- Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF) ---
//
// e.g. "𝗂𝗀𝗇𝗈𝗋𝗲" (Sans-Serif Bold) or "𝑖𝑔𝑛𝑜𝑟𝑒" (Italic) for "ignore" —
// visually near-identical to plain Latin text in most renderers but a
// completely different set of codepoints, defeating naive keyword
// matching. mathAlphanumeric (mathalphanumeric.go) is generated from and
// verified against the real Unicode character database.

func mayContainMathAlphanumeric(data []byte) bool {
	for _, r := range string(data) {
		if _, ok := mathAlphanumeric[r]; ok {
			return true
		}
	}
	return false
}

func normalizeMathAlphanumeric(data []byte) ([]replacement, []string) {
	var out []replacement
	for offset, r := range string(data) {
		ascii, ok := mathAlphanumeric[r]
		if !ok {
			continue
		}
		out = append(out, replacement{
			start: offset, end: offset + utf8.RuneLen(r),
			data: []byte{ascii}, detail: "normalized mathematical alphanumeric symbol",
		})
	}
	return out, nil
}

// --- Fullwidth Forms (U+FF01-U+FF5E, plus the ideographic space U+3000) ---
//
// e.g. "ｉｇｎｏｒｅ" (fullwidth Latin) for "ignore" — a CJK-typesetting
// convention repurposed the same way as mathematical alphanumerics.

func mayContainFullwidth(data []byte) bool {
	for _, r := range string(data) {
		if r == 0x3000 || (r >= 0xff01 && r <= 0xff5e) {
			return true
		}
	}
	return false
}

func normalizeFullwidth(data []byte) ([]replacement, []string) {
	var out []replacement
	for offset, r := range string(data) {
		var ascii byte
		switch {
		case r == 0x3000:
			ascii = ' '
		case r >= 0xff01 && r <= 0xff5e:
			ascii = byte(r - 0xfee0)
		default:
			continue
		}
		out = append(out, replacement{
			start: offset, end: offset + utf8.RuneLen(r),
			data: []byte{ascii}, detail: "normalized fullwidth form",
		})
	}
	return out, nil
}

// --- Braille Pattern byte encoding (U+2800-U+28FF) ---
//
// A common steganographic convention encodes arbitrary bytes directly as
// Braille Pattern characters (codepoint - U+2800 == the byte value,
// since the block's 256 codepoints correspond 1:1 to the 256 possible
// 8-dot patterns) — not real Braille transliteration of language text,
// which follows entirely different encoding tables and would not
// generally decode to printable ASCII this way. Only a run of at least
// brailleMinRun consecutive Braille Pattern characters is considered (a
// single incidental Braille character is not enough signal), and — like
// every other decode transform in this package — the decoded bytes are
// only kept as a replacement when they pass the same printable() check
// base64/hex decoding already uses; non-printable output (which is what
// naive byte-decoding of genuine Braille prose would almost always
// produce) is silently left alone rather than surfaced as a
// misleading "reconstruction".
const brailleMinRun = 4

var braillePattern = regexp.MustCompile(fmt.Sprintf(`[\x{2800}-\x{28FF}]{%d,}`, brailleMinRun))

func mayContainBrailleRun(data []byte) bool {
	return braillePattern.Match(data)
}

func decodeBraille(data []byte) ([]replacement, []string) {
	var out []replacement
	for _, index := range braillePattern.FindAllIndex(data, -1) {
		run := string(data[index[0]:index[1]])
		decoded := make([]byte, 0, len(run))
		for _, r := range run {
			decoded = append(decoded, byte(r-0x2800))
		}
		if !printable(decoded) {
			continue
		}
		out = append(out, replacement{
			start: index[0], end: index[1], data: decoded,
			detail: "decoded printable Braille-pattern byte encoding",
		})
	}
	return out, nil
}

// --- Shell/script line-continuation joining ---
//
// A trailing backslash immediately before a line ending is a literal
// continuation marker in both POSIX shell and Python: the backslash and
// the newline are removed and the following line's text abuts directly
// to what preceded the backslash, with no reordering — so a dangerous
// command deliberately fragmented across several lines
//
//	rm \
//	   -rf \
//	   /
//
// reconstructs to a single logical line ("rm    -rf    /", which parses
// identically to "rm -rf /" — whitespace runs are not significant to
// either language's tokenizer) that the existing Bash/Python analyzers
// can match exactly as they would the unfragmented form, with their own
// already-defined rule severity — no separate "severity preservation"
// logic is needed once the fragmented form reconstructs to what an
// existing rule already matches.
var shellContinuation = regexp.MustCompile(`\\\r?\n`)

func joinShellLineContinuations(data []byte) ([]replacement, []string) {
	var out []replacement
	for _, index := range shellContinuation.FindAllIndex(data, -1) {
		out = append(out, replacement{start: index[0], end: index[1], detail: "joined a backslash line continuation"})
	}
	return out, nil
}

package artifact

import (
	"unicode/utf16"
	"unicode/utf8"
)

// Charset-smuggling defense: several analyzers scope themselves to "text"
// files via a check that boils down to "no NUL bytes and valid UTF-8" (see
// internal/analyzer.isText). Content encoded as UTF-16 — a single BOM away
// from any plain-text editor rendering it normally — fails that check and
// is silently treated as out-of-scope/binary, even though it is exactly
// the kind of natural-language content (a SKILL.md, a manifest) those
// analyzers exist to inspect. A prompt-injection payload saved as UTF-16
// therefore reaches every text-scoped rule invisibly.
//
// canonicalizeText closes this at the source: it detects a file's text
// encoding once, at artifact load time, and — for a recognized non-UTF-8
// text encoding — transcodes it to canonical UTF-8 before any analyzer
// ever sees it. Every analyzer that already treats file.Data as text
// benefits automatically, with no per-analyzer changes: after
// canonicalization, file.Data for a UTF-16 source is genuine UTF-8 text
// that internal/analyzer.isText's existing check correctly recognizes.
//
// Binary content (executables, archives, model weights, images, ...)
// round-trips completely unchanged: this function only ever transforms
// bytes it can confidently decode as UTF-8-with-BOM or UTF-16, and falls
// back to the original bytes for everything else. File.SHA256 is always
// computed from the original, untranscoded bytes (see newFile), so
// content-addressing and attestation digests are unaffected by this.
func canonicalizeText(data []byte) ([]byte, string) {
	if len(data) == 0 {
		return data, "utf-8"
	}
	switch {
	case len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF:
		if rest := data[3:]; utf8.Valid(rest) {
			return rest, "utf-8-bom"
		}
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		if text, ok := decodeUTF16(data[2:], false); ok {
			return text, "utf-16le"
		}
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		if text, ok := decodeUTF16(data[2:], true); ok {
			return text, "utf-16be"
		}
	}
	if utf8.Valid(data) && !containsNUL(data) {
		return data, "utf-8"
	}
	if bigEndian, ok := detectUnmarkedUTF16(data); ok {
		if text, ok := decodeUTF16(data, bigEndian); ok {
			if bigEndian {
				return text, "utf-16be"
			}
			return text, "utf-16le"
		}
	}
	return data, "binary"
}

func containsNUL(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

// decodeUTF16 converts raw UTF-16 code units (any BOM already stripped) to
// UTF-8. It rejects anything that doesn't decode to complete, valid
// UTF-16 — an odd byte length or an unpaired surrogate leaves the content
// as opaque binary rather than guessing at a lossy or corrupted decode.
func decodeUTF16(data []byte, bigEndian bool) ([]byte, bool) {
	if len(data)%2 != 0 {
		return nil, false
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		if bigEndian {
			units[i] = uint16(data[2*i])<<8 | uint16(data[2*i+1])
		} else {
			units[i] = uint16(data[2*i+1])<<8 | uint16(data[2*i])
		}
	}
	runes := utf16.Decode(units)
	for _, r := range runes {
		if r == utf8.RuneError {
			return nil, false
		}
	}
	return []byte(string(runes)), true
}

// detectUnmarkedUTF16 heuristically recognizes BOM-less UTF-16: text in
// the Basic Latin range (the overwhelming majority of natural-language
// and code content) encoded as UTF-16 has a NUL high byte in essentially
// every code unit, on a fixed side depending on endianness. Requiring a
// clear, near-total majority on exactly one side (and none at all on the
// other) avoids misclassifying ordinary binary data that merely happens
// to contain some NUL bytes.
func detectUnmarkedUTF16(data []byte) (bigEndian, ok bool) {
	if len(data) < 16 || len(data)%2 != 0 {
		return false, false
	}
	pairs := len(data) / 2
	// evenZero/oddZero count zero bytes by position parity within each
	// 2-byte unit, not by byte significance — which one corresponds to
	// the code unit's high (significant) byte depends on endianness:
	// LE stores the high byte at the odd position, BE at the even one.
	evenZero, oddZero := 0, 0
	for i := 0; i < pairs; i++ {
		if data[2*i] == 0 {
			evenZero++
		}
		if data[2*i+1] == 0 {
			oddZero++
		}
	}
	const threshold = 0.90
	// LE Basic-Latin text: high byte (odd position) is zero, low byte
	// (even position, the actual ASCII value) essentially never is.
	if float64(oddZero) >= threshold*float64(pairs) && evenZero == 0 {
		return false, true
	}
	// BE Basic-Latin text: the reverse — high byte at the even position.
	if float64(evenZero) >= threshold*float64(pairs) && oddZero == 0 {
		return true, true
	}
	return false, false
}

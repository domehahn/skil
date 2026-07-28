package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/domehahn/skil/pkg/skil"
)

type RulePattern struct {
	Rule       skil.Rule
	Pattern    *regexp.Regexp
	Negative   *regexp.Regexp
	Confidence float64
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func normalizeEvidence(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max]) + "…"
}

func lines(data []byte) []string {
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

func extension(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "dockerfile" || base == "makefile" {
		return base
	}
	return strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
}

func isText(file skil.File) bool {
	for _, b := range file.Data {
		if b == 0 {
			return false
		}
	}
	return utf8.Valid(file.Data)
}

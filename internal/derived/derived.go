// Package derived constructs deterministic, provenance-preserving alternative
// security views of immutable artifact bytes. It performs no network access,
// model calls, or execution.
package derived

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/domehahn/skil/pkg/skil"
)

type Budget struct {
	MaxViews int
	MaxDepth int
	MaxBytes int64
}

type Span struct {
	Start int
	End   int
}

type View struct {
	Evidence skil.DerivedViewEvidence
	Data     []byte
	mapping  []Span
	changed  []bool
}

type Result struct {
	Views       []View
	Complete    bool
	Bytes       int64
	MaxDepth    int
	Exceeded    []string
	Limitations []string
}

type transformer struct {
	kind     string
	mayApply func([]byte) bool
	apply    func([]byte) ([]replacement, []string)
}

type replacement struct {
	start  int
	end    int
	data   []byte
	detail string
}

const maxTokenBytes = 1 << 20

var (
	base64Token       = regexp.MustCompile(`(?:^|[^A-Za-z0-9_+/=-])([A-Za-z0-9_+/-]{16,}={0,2})(?:$|[^A-Za-z0-9_+/=-])`)
	hexToken          = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])(?:0x)?([0-9a-f]{16,})(?:$|[^0-9a-f])`)
	urlToken          = regexp.MustCompile(`[A-Za-z0-9._~/%-]*%[0-9A-Fa-f]{2}[A-Za-z0-9._~/%-]*`)
	doubleQuote       = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	doubleConcat      = regexp.MustCompile(`"(?:\\.|[^"\\])*"(?:[ \t]*\+[ \t]*"(?:\\.|[^"\\])*")+`)
	spacedWord        = regexp.MustCompile(`\b(?:[A-Za-z0-9][ \t]){3,}[A-Za-z0-9]\b`)
	markerDecl        = regexp.MustCompile(`(?mi)^(?:obfuscation-marker|remove-marker|separator-character)[ \t]*[:=][ \t]*["']?([^A-Za-z0-9[:space:]"'])["']?[ \t]*$`)
	markerDirective   = regexp.MustCompile(`(?mi)^(?:obfuscation-marker|remove-marker|separator-character)[ \t]*[:=][ \t]*(.+?)[ \t]*$`)
	explicitBadBase64 = regexp.MustCompile(`(?i)\bbase64[ \t]*:[ \t]*([^\s]+)`)
	explicitBadHex    = regexp.MustCompile(`(?i)\bhex[ \t]*:[ \t]*([^\s]+)`)
	explicitBadURL    = regexp.MustCompile(`(?i)\burl-?encoded[ \t]*:[ \t]*([^\s]+)`)
)

var transformations = []transformer{
	{kind: "unicode-default-ignorables", mayApply: mayContainDefaultIgnorable, apply: removeDefaultIgnorables},
	{kind: "unicode-bidi-controls", mayApply: mayContainBidi, apply: removeBidiControls},
	{kind: "unicode-confusable-normalization", mayApply: mayContainConfusable, apply: normalizeConfusables},
	{kind: "inter-character-spacing", mayApply: func(data []byte) bool { return spacedWord.Match(data) }, apply: collapseInterCharacterSpacing},
	{kind: "declared-marker-removal", mayApply: func(data []byte) bool { return markerDirective.Match(data) }, apply: removeDeclaredMarker},
	{kind: "base64", mayApply: func(data []byte) bool { return base64Token.Match(data) || explicitBadBase64.Match(data) }, apply: decodeBase64},
	{kind: "hex", mayApply: func(data []byte) bool { return hexToken.Match(data) || explicitBadHex.Match(data) }, apply: decodeHex},
	{kind: "url-encoding", mayApply: func(data []byte) bool { return urlToken.Match(data) || explicitBadURL.Match(data) }, apply: decodeURL},
	{kind: "escaped-string", mayApply: func(data []byte) bool { return doubleQuote.Match(data) && strings.Contains(string(data), `\`) }, apply: decodeEscapedStrings},
	{kind: "simple-string-concatenation", mayApply: func(data []byte) bool { return doubleConcat.Match(data) }, apply: joinStringConcatenation},
}

// Build derives views breadth-first in a fixed transformation order. Original
// files are never changed and are not included in Result.Views.
func Build(ctx context.Context, artifact skil.Artifact, budget Budget) Result {
	result := Result{Complete: true}
	if budget.MaxViews <= 0 || budget.MaxDepth <= 0 || budget.MaxBytes <= 0 {
		result.Complete = false
		result.Limitations = []string{"derived security view budget is disabled or invalid"}
		return result
	}
	files := append([]skil.File(nil), artifact.Files...)
	sort.Slice(files, func(i, j int) bool {
		if files[i].Path != files[j].Path {
			return files[i].Path < files[j].Path
		}
		return digest(files[i].Data) < digest(files[j].Data)
	})
	for _, file := range files {
		if ctx.Err() != nil {
			addLimitation(&result, file.Path+": derived view construction cancelled")
			break
		}
		if !utf8.Valid(file.Data) || len(file.Data) == 0 {
			continue
		}
		buildFile(ctx, file, budget, &result)
	}
	return result
}

func buildFile(ctx context.Context, file skil.File, budget Budget, result *Result) {
	originDigest := digest(file.Data)
	root := View{Data: append([]byte(nil), file.Data...), mapping: make([]Span, len(file.Data)), changed: make([]bool, len(file.Data))}
	for index := range root.mapping {
		root.mapping[index] = Span{Start: index, End: index + 1}
	}
	queue := []View{root}
	seen := map[string]bool{digest(file.Data): true}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			addLimitation(result, file.Path+": derived view construction cancelled")
			return
		}
		current := queue[0]
		queue = queue[1:]
		used := usedKinds(current.Evidence.Transformations)
		if current.Evidence.Depth >= budget.MaxDepth {
			for _, transform := range transformations {
				if !used[transform.kind] && transform.mayApply(current.Data) {
					replacements, issues := transform.apply(current.Data)
					for _, issue := range issues {
						addLimitation(result, file.Path+": "+transform.kind+": "+issue)
					}
					if len(replacements) > 0 {
						markExceeded(result, "derived_depth", fmt.Sprintf("%s: maximum derived view depth %d reached", file.Path, budget.MaxDepth))
						break
					}
				}
			}
			continue
		}
		for _, transform := range transformations {
			if used[transform.kind] || !transform.mayApply(current.Data) {
				continue
			}
			replacements, issues := transform.apply(current.Data)
			for _, issue := range issues {
				addLimitation(result, file.Path+": "+transform.kind+": "+issue)
			}
			if len(replacements) == 0 {
				continue
			}
			next, ok := applyReplacements(current, transform.kind, replacements)
			if !ok || len(next.Data) > maxTokenBytes*16 {
				addLimitation(result, file.Path+": "+transform.kind+": output exceeds safe per-view bound")
				continue
			}
			contentDigest := digest(next.Data)
			if seen[contentDigest] {
				continue
			}
			if len(result.Views) >= budget.MaxViews {
				markExceeded(result, "derived_views", fmt.Sprintf("%s: maximum derived view count %d reached", file.Path, budget.MaxViews))
				return
			}
			if result.Bytes+int64(len(next.Data)) > budget.MaxBytes {
				markExceeded(result, "derived_bytes", fmt.Sprintf("%s: maximum derived bytes %d reached", file.Path, budget.MaxBytes))
				return
			}
			seen[contentDigest] = true
			next.Evidence.SourcePath = file.Path
			next.Evidence.SourceDigest = originDigest
			next.Evidence.Digest = contentDigest
			next.Evidence.Depth = current.Evidence.Depth + 1
			next.Evidence.ID = "dv-" + digest([]byte(file.Path + "\x00" + originDigest + "\x00" + contentDigest + "\x00" + transformationIdentity(next.Evidence.Transformations)))[:20]
			result.Views = append(result.Views, next)
			result.Bytes += int64(len(next.Data))
			if next.Evidence.Depth > result.MaxDepth {
				result.MaxDepth = next.Evidence.Depth
			}
			queue = append(queue, next)
		}
	}
}

func applyReplacements(view View, kind string, replacements []replacement) (View, bool) {
	sort.Slice(replacements, func(i, j int) bool { return replacements[i].start < replacements[j].start })
	var data []byte
	var mapping []Span
	var changed []bool
	var removalOutputs []int
	steps := append([]skil.TransformationStep(nil), view.Evidence.Transformations...)
	cursor := 0
	for _, item := range replacements {
		if item.start < cursor || item.start < 0 || item.end <= item.start || item.end > len(view.Data) {
			return View{}, false
		}
		data = append(data, view.Data[cursor:item.start]...)
		mapping = append(mapping, view.mapping[cursor:item.start]...)
		changed = append(changed, view.changed[cursor:item.start]...)
		outputStart := len(data)
		original := originalSpan(view.mapping, item.start, item.end)
		data = append(data, item.data...)
		for range item.data {
			mapping = append(mapping, original)
			changed = append(changed, true)
		}
		if len(item.data) == 0 {
			removalOutputs = append(removalOutputs, outputStart)
		}
		steps = append(steps, skil.TransformationStep{
			Kind: kind, InputStart: item.start, InputEnd: item.end,
			OutputStart: outputStart, OutputEnd: len(data),
			OriginalStart: original.Start, OriginalEnd: original.End, Detail: item.detail,
		})
		cursor = item.end
	}
	data = append(data, view.Data[cursor:]...)
	mapping = append(mapping, view.mapping[cursor:]...)
	changed = append(changed, view.changed[cursor:]...)
	for _, output := range removalOutputs {
		if output < len(changed) {
			changed[output] = true
		} else if output > 0 {
			changed[output-1] = true
		}
	}
	return View{Evidence: skil.DerivedViewEvidence{Transformations: steps}, Data: data, mapping: mapping, changed: changed}, true
}

// OriginalSpan maps an output byte range to the smallest containing original
// byte span. It also reports whether the range intersects transformed output.
func (v View) OriginalSpan(start, end int) (Span, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(v.mapping) {
		end = len(v.mapping)
	}
	if end <= start {
		return Span{}, false
	}
	span := originalSpan(v.mapping, start, end)
	changed := false
	for _, value := range v.changed[start:end] {
		changed = changed || value
	}
	return span, changed
}

func originalSpan(mapping []Span, start, end int) Span {
	span := Span{Start: mapping[start].Start, End: mapping[start].End}
	for _, item := range mapping[start+1 : end] {
		if item.Start < span.Start {
			span.Start = item.Start
		}
		if item.End > span.End {
			span.End = item.End
		}
	}
	return span
}

func removeDefaultIgnorables(data []byte) ([]replacement, []string) {
	return runeRemovals(data, func(r rune, previous, next rune) bool {
		if r == '\u200d' && isEmojiRune(previous) && isEmojiRune(next) {
			return false
		}
		switch r {
		case '\u00ad', '\u034f', '\u061c', '\u180e', '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff':
			return true
		}
		return r >= 0xfe00 && r <= 0xfe0f || r >= 0xe0000 && r <= 0xe007f
	}, "removed Unicode default-ignorable code point"), nil
}

func removeBidiControls(data []byte) ([]replacement, []string) {
	return runeRemovals(data, func(r rune, _, _ rune) bool {
		return r == '\u200e' || r == '\u200f' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069'
	}, "removed Unicode bidi control"), nil
}

func normalizeConfusables(data []byte) ([]replacement, []string) {
	confusables := map[rune]rune{
		'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i',
		'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X',
		'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'χ': 'x',
	}
	var out []replacement
	for offset, r := range string(data) {
		latin, ok := confusables[r]
		if !ok {
			continue
		}
		out = append(out, replacement{start: offset, end: offset + utf8.RuneLen(r), data: []byte(string(latin)), detail: fmt.Sprintf("normalized U+%04X", r)})
	}
	return out, nil
}

func collapseInterCharacterSpacing(data []byte) ([]replacement, []string) {
	indices := spacedWord.FindAllIndex(data, -1)
	out := make([]replacement, 0, len(indices))
	for _, index := range indices {
		collapsed := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, string(data[index[0]:index[1]]))
		out = append(out, replacement{start: index[0], end: index[1], data: []byte(collapsed), detail: "collapsed single-character spacing"})
	}
	return out, nil
}

func removeDeclaredMarker(data []byte) ([]replacement, []string) {
	match := markerDecl.FindSubmatchIndex(data)
	if len(match) < 4 {
		if markerDirective.Match(data) {
			return nil, []string{"explicit marker declaration must name exactly one punctuation character"}
		}
		return nil, nil
	}
	marker := append([]byte(nil), data[match[2]:match[3]]...)
	if len(marker) != 1 {
		return nil, []string{"declared marker is not one ASCII byte"}
	}
	var out []replacement
	for index := match[1]; index < len(data); index++ {
		if data[index] == marker[0] {
			out = append(out, replacement{start: index, end: index + 1, detail: fmt.Sprintf("removed explicitly declared marker 0x%02x", marker[0])})
		}
	}
	return out, nil
}

func decodeBase64(data []byte) ([]replacement, []string) {
	var out []replacement
	for _, match := range base64Token.FindAllSubmatchIndex(data, -1) {
		start, end := match[2], match[3]
		if end-start > maxTokenBytes {
			return out, []string{"Base64 token exceeds safe decode bound"}
		}
		encoded := data[start:end]
		var decoded []byte
		var err error
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err = encoding.DecodeString(string(encoded))
			if err == nil {
				break
			}
		}
		if err == nil && printable(decoded) {
			out = append(out, replacement{start: start, end: end, data: decoded, detail: "decoded printable Base64 token"})
		}
	}
	return out, invalidExplicitEncoding(data, explicitBadBase64, func(value string) bool {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if _, err := encoding.DecodeString(value); err == nil {
				return true
			}
		}
		return false
	}, "explicit Base64 declaration is malformed")
}

func decodeHex(data []byte) ([]replacement, []string) {
	var out []replacement
	for _, match := range hexToken.FindAllSubmatchIndex(data, -1) {
		start, end := match[2], match[3]
		if (end-start)%2 != 0 || end-start > maxTokenBytes*2 {
			continue
		}
		decoded, err := hex.DecodeString(string(data[start:end]))
		if err == nil && printable(decoded) {
			out = append(out, replacement{start: start, end: end, data: decoded, detail: "decoded printable hexadecimal token"})
		}
	}
	return out, invalidExplicitEncoding(data, explicitBadHex, func(value string) bool {
		value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
		_, err := hex.DecodeString(value)
		return len(value)%2 == 0 && err == nil
	}, "explicit hexadecimal declaration is malformed")
}

func decodeURL(data []byte) ([]replacement, []string) {
	var out []replacement
	for _, index := range urlToken.FindAllIndex(data, -1) {
		decoded, err := url.PathUnescape(string(data[index[0]:index[1]]))
		if err == nil {
			out = append(out, replacement{start: index[0], end: index[1], data: []byte(decoded), detail: "decoded percent-encoded token"})
		}
	}
	return out, invalidExplicitEncoding(data, explicitBadURL, func(value string) bool {
		_, err := url.PathUnescape(value)
		return err == nil
	}, "explicit URL-encoded declaration is malformed")
}

func decodeEscapedStrings(data []byte) ([]replacement, []string) {
	var out []replacement
	for _, index := range doubleQuote.FindAllIndex(data, -1) {
		literal := string(data[index[0]:index[1]])
		if !strings.Contains(literal, `\`) {
			continue
		}
		decoded, err := strconv.Unquote(literal)
		if err != nil {
			return out, []string{"quoted escaped string is malformed"}
		}
		reencoded := strconv.Quote(decoded)
		if reencoded != literal {
			out = append(out, replacement{start: index[0], end: index[1], data: []byte(reencoded), detail: "decoded quoted escape sequences"})
		}
	}
	return out, nil
}

func joinStringConcatenation(data []byte) ([]replacement, []string) {
	var out []replacement
	for _, index := range doubleConcat.FindAllIndex(data, -1) {
		segment := data[index[0]:index[1]]
		literals := doubleQuote.FindAll(segment, -1)
		var joined strings.Builder
		valid := true
		for _, literal := range literals {
			value, err := strconv.Unquote(string(literal))
			if err != nil {
				valid = false
				break
			}
			joined.WriteString(value)
		}
		if valid {
			out = append(out, replacement{start: index[0], end: index[1], data: []byte(strconv.Quote(joined.String())), detail: fmt.Sprintf("joined %d adjacent literals", len(literals))})
		}
	}
	return out, nil
}

func runeRemovals(data []byte, remove func(rune, rune, rune) bool, detail string) []replacement {
	runes := []rune(string(data))
	var offsets []int
	for offset := range string(data) {
		offsets = append(offsets, offset)
	}
	var out []replacement
	for index, r := range runes {
		var previous, next rune
		if index > 0 {
			previous = runes[index-1]
		}
		if index+1 < len(runes) {
			next = runes[index+1]
		}
		if remove(r, previous, next) {
			out = append(out, replacement{start: offsets[index], end: offsets[index] + utf8.RuneLen(r), detail: detail})
		}
	}
	return out
}

func mayContainDefaultIgnorable(data []byte) bool {
	for _, r := range string(data) {
		switch r {
		case '\u00ad', '\u034f', '\u061c', '\u180e', '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff':
			return true
		}
		if r >= 0xfe00 && r <= 0xfe0f || r >= 0xe0000 && r <= 0xe007f {
			return true
		}
	}
	return false
}

func mayContainBidi(data []byte) bool {
	return strings.ContainsAny(string(data), "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
}

func mayContainConfusable(data []byte) bool {
	for _, r := range string(data) {
		if unicode.In(r, unicode.Cyrillic, unicode.Greek) {
			return true
		}
	}
	return false
}

func invalidExplicitEncoding(data []byte, pattern *regexp.Regexp, valid func(string) bool, message string) []string {
	for _, match := range pattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 && !valid(string(match[1])) {
			return []string{message}
		}
	}
	return nil
}

func printable(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) {
		return false
	}
	printableCount, total := 0, 0
	for _, r := range string(data) {
		total++
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printableCount++
		}
	}
	return total > 0 && printableCount*100/total >= 85
}

func isEmojiRune(r rune) bool {
	return r >= 0x1f300 && r <= 0x1faff || r >= 0x2600 && r <= 0x27bf || r >= 0x1f1e6 && r <= 0x1f1ff || r >= 0xfe00 && r <= 0xfe0f
}

func usedKinds(steps []skil.TransformationStep) map[string]bool {
	out := map[string]bool{}
	for _, step := range steps {
		out[step.Kind] = true
	}
	return out
}

func transformationIdentity(steps []skil.TransformationStep) string {
	var parts []string
	for _, step := range steps {
		parts = append(parts, step.Kind+":"+strconv.Itoa(step.OriginalStart)+":"+strconv.Itoa(step.OriginalEnd))
	}
	return strings.Join(parts, "|")
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func addLimitation(result *Result, limitation string) {
	for _, existing := range result.Limitations {
		if existing == limitation {
			result.Complete = false
			return
		}
	}
	result.Complete = false
	result.Limitations = append(result.Limitations, limitation)
}

func markExceeded(result *Result, dimension, limitation string) {
	for _, existing := range result.Exceeded {
		if existing == dimension {
			addLimitation(result, limitation)
			return
		}
	}
	result.Exceeded = append(result.Exceeded, dimension)
	sort.Strings(result.Exceeded)
	addLimitation(result, limitation)
}

package derived

import "strings"

type SyntaxOwner string

const (
	OwnerRawText       SyntaxOwner = "RAW_TEXT"
	OwnerMarkdownProse SyntaxOwner = "MARKDOWN_PROSE"
	OwnerMarkdownCode  SyntaxOwner = "MARKDOWN_CODE"
	OwnerJSONString    SyntaxOwner = "JSON_STRING"
	OwnerYAMLScalar    SyntaxOwner = "YAML_SCALAR"
	OwnerShellCode     SyntaxOwner = "SHELL_CODE"
	OwnerPythonCode    SyntaxOwner = "PYTHON_CODE"
	OwnerHTMLBlock     SyntaxOwner = "HTML_BLOCK"
	OwnerUnknown       SyntaxOwner = "UNKNOWN"
)

type OwnedSpan struct {
	Start, End int
	Owner      SyntaxOwner
	Language   string
}

// ClassifySyntaxOwnership preserves byte offsets and distinguishes Markdown
// prose from fenced executable content. It intentionally does not guess that
// an unknown fence is executable.
func ClassifySyntaxOwnership(path string, data []byte, maxSpans int) ([]OwnedSpan, bool) {
	if maxSpans <= 0 {
		maxSpans = 4096
	}
	text := string(data)
	lower := strings.ToLower(path)
	if !strings.HasSuffix(lower, ".md") && !strings.HasSuffix(lower, ".markdown") {
		return []OwnedSpan{{0, len(data), ownerForPath(lower), ""}}, true
	}
	var spans []OwnedSpan
	pos := 0
	inFence := false
	fenceStart := 0
	language := ""
	for pos < len(text) {
		lineEnd := strings.IndexByte(text[pos:], '\n')
		if lineEnd < 0 {
			lineEnd = len(text) - pos
		} else {
			lineEnd++
		}
		line := text[pos : pos+lineEnd]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			if !inFence {
				if pos > fenceStart {
					spans = append(spans, OwnedSpan{fenceStart, pos, OwnerMarkdownProse, ""})
				}
				inFence = true
				language = strings.TrimSpace(trimmed[3:])
				fenceStart = pos
			}
			if inFence && pos != fenceStart {
				spans = append(spans, OwnedSpan{fenceStart, pos + lineEnd, OwnerMarkdownCode, language})
				inFence = false
				fenceStart = pos + lineEnd
				language = ""
			}
		}
		pos += lineEnd
		if len(spans) >= maxSpans {
			return spans, false
		}
	}
	if fenceStart < len(text) {
		owner := OwnerMarkdownProse
		if inFence {
			owner = OwnerMarkdownCode
		}
		spans = append(spans, OwnedSpan{fenceStart, len(text), owner, language})
	}
	return spans, !inFence
}

func ownerForPath(path string) SyntaxOwner {
	switch {
	case strings.HasSuffix(path, ".py"):
		return OwnerPythonCode
	case strings.HasSuffix(path, ".sh") || strings.HasSuffix(path, ".bash"):
		return OwnerShellCode
	case strings.HasSuffix(path, ".json"):
		return OwnerJSONString
	case strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml"):
		return OwnerYAMLScalar
	case strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm"):
		return OwnerHTMLBlock
	case strings.HasSuffix(path, ".txt"):
		return OwnerRawText
	default:
		return OwnerUnknown
	}
}

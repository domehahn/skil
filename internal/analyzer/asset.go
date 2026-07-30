package analyzer

import (
	"bytes"
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// Asset analyzes non-code artifact types a skill may bundle (SVG, PDF,
// Office documents, and binaries disguised with a mismatched extension).
// These formats can carry active/executable content even though they are
// not "code" in the sense skil's other analyzers scope to, and a
// mismatched-extension binary is invisible to every extension-scoped
// analyzer in the codebase. It only reads and pattern-matches bytes; it
// never renders, opens, or executes any scanned asset.
type Asset struct{}

func NewAsset() *Asset { return &Asset{} }

func (a *Asset) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.asset", Version: "1.0.0",
		Domain: "asset-malware", Subdomain: "active-content",
		Categories:    []string{"asset-security"},
		AnalysisTypes: []string{"asset"}, SupportedTypes: []string{"svg", "pdf", "wasm", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "*"}}
}

func (a *Asset) Rules() []skil.Rule {
	return []skil.Rule{
		{ID: "SKIL-ASSET-SVG-SCRIPT", Title: "Active content in SVG", Category: "asset-security",
			Severity: skil.SeverityHigh, Analysis: "asset", AppliesTo: []string{"svg"},
			Description: "An SVG image embeds a <script> element or an inline event-handler attribute, letting it execute JavaScript when rendered.",
			Remediation: "Strip scripts and event-handler attributes from SVG assets, or sanitize them before rendering."},
		{ID: "SKIL-ASSET-PDF-JAVASCRIPT", Title: "Embedded JavaScript in PDF", Category: "asset-security",
			Severity: skil.SeverityHigh, Analysis: "asset", AppliesTo: []string{"pdf"},
			Description: "A PDF document embeds a JavaScript action, which can execute when the document is opened in a compatible viewer.",
			Remediation: "Remove embedded JavaScript from the PDF or regenerate it from a trusted, script-free source."},
		{ID: "SKIL-ASSET-OFFICE-MACRO", Title: "Embedded Office macro", Category: "asset-security",
			Severity: skil.SeverityCritical, Analysis: "asset", AppliesTo: []string{"docx", "xlsx", "pptx", "docm", "xlsm", "pptm"},
			Description: "An Office document embeds a VBA macro project, which can execute code when the document is opened.",
			Remediation: "Remove the macro project or replace the document with a macro-free format."},
		{ID: "SKIL-ASSET-WASM-IMPORT", Title: "WebAssembly binary with import section", Category: "asset-security",
			Severity: skil.SeverityMedium, Analysis: "asset", AppliesTo: []string{"wasm"},
			Description: "A WebAssembly binary contains an import section, meaning it can invoke host functions (system calls, API access) when executed.",
			Remediation: "Review and allowlist the WASM module's imported functions before execution in a skill context."},
		{ID: "SKIL-ASSET-FILE-TYPE-MISMATCH", Title: "File content does not match its extension", Category: "asset-security",
			Severity: skil.SeverityCritical, Analysis: "asset",
			Description: "A file's actual content (a native executable, script interpreter, or archive) does not match what its extension implies, a classic smuggling/polyglot technique.",
			Remediation: "Verify the file's true type and remove or rename any disguised executable content."},
	}
}

var (
	svgScriptTag  = regexp.MustCompile(`(?i)<script\b|on(?:load|click|mouseover|error|focus)\s*=`)
	pdfJavaScript = regexp.MustCompile(`/JavaScript\b|/JS\s*[\(<]`)
)

// nonExecutableExtensions are extensions where legitimate content should
// never be a native executable, script interpreter shebang binary, or
// archive — a mismatch here is a strong disguised-payload signal. Formats
// that are legitimately zip-based (docx/xlsx/keras/etc.) are excluded since
// zip-magic bytes there are expected, not a mismatch.
var nonExecutableExtensions = map[string]bool{
	"txt": true, "md": true, "json": true, "yaml": true, "yml": true,
	"csv": true, "svg": true, "png": true, "jpg": true, "jpeg": true,
	"gif": true, "ico": true, "log": true, "conf": true, "cfg": true, "ini": true,
}

func (a *Asset) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		ext := strings.ToLower(extension(file.Path))
		switch ext {
		case "wasm":
			if wasmHasImportSection(file.Data) {
				out = append(out, makeFinding(RulePattern{Rule: a.ruleByID("SKIL-ASSET-WASM-IMPORT"), Confidence: .9},
					file, 1, "WebAssembly binary with import section"))
			}
		case "svg":
			if svgScriptTag.Match(file.Data) {
				out = append(out, makeFinding(RulePattern{Rule: a.ruleByID("SKIL-ASSET-SVG-SCRIPT"), Confidence: .9},
					file, lineOf(file.Data, svgScriptTag), "active content in SVG"))
			}
		case "pdf":
			if pdfJavaScript.Match(file.Data) {
				out = append(out, makeFinding(RulePattern{Rule: a.ruleByID("SKIL-ASSET-PDF-JAVASCRIPT"), Confidence: .85},
					file, 1, "embedded JavaScript action in PDF"))
			}
		case "docx", "xlsx", "pptx", "docm", "xlsm", "pptm":
			if looksLikeZip(file.Data) {
				members, err := readBoundedZipMembers(file.Data, "vbaProject.bin")
				if err == nil && len(members) > 0 {
					out = append(out, makeFinding(RulePattern{Rule: a.ruleByID("SKIL-ASSET-OFFICE-MACRO"), Confidence: .95},
						file, 1, "embedded VBA macro project"))
				}
			}
		}
		if nonExecutableExtensions[ext] {
			if kind := disguisedBinaryKind(file.Data); kind != "" {
				finding := makeFinding(RulePattern{Rule: a.ruleByID("SKIL-ASSET-FILE-TYPE-MISMATCH"), Confidence: .95},
					file, 1, kind+" content disguised as ."+ext)
				finding.Evidence["actual_type"] = kind
				out = append(out, finding)
			}
		}
	}
	return out, nil
}

func (a *Asset) ruleByID(id string) skil.Rule {
	for _, r := range a.Rules() {
		if r.ID == id {
			return r
		}
	}
	return skil.Rule{ID: id}
}

func looksLikeWasm(data []byte) bool {
	return len(data) >= 8 && bytes.Equal(data[:4], []byte{0x00, 'a', 's', 'm'}) &&
		bytes.Equal(data[4:8], []byte{0x01, 0x00, 0x00, 0x00})
}

// wasmHasImportSection parses a WASM binary header to determine whether
// section ID 2 (import section) is present, indicating the module invokes
// host functions when executed.
func wasmHasImportSection(data []byte) bool {
	if !looksLikeWasm(data) {
		return false
	}
	i := 8
	for i < len(data) {
		if i >= len(data) {
			return false
		}
		sectionID := data[i]
		i++
		if i >= len(data) {
			return false
		}
		size, n := decodeULEB128(data[i:])
		if n <= 0 {
			return false
		}
		i += n
		if sectionID == 2 {
			return true
		}
		// skip section payload
		i += size
	}
	return false
}

// decodeULEB128 reads a WASM-format unsigned LEB128 encoded integer from
// data and returns the value and the number of bytes consumed.
func decodeULEB128(data []byte) (int, int) {
	result := 0
	shift := 0
	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		result |= int(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return 0, 0
}

// disguisedBinaryKind reports the true type of content that is a native
// executable, script interpreter, or archive, based on its magic bytes,
// or "" if it looks like ordinary text/data.
func disguisedBinaryKind(data []byte) string {
	switch {
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "Windows PE executable"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF executable"
	case len(data) >= 4 && (bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) ||
		bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
		bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(data[:4], []byte{0xce, 0xfa, 0xed, 0xfe})):
		return "Mach-O executable"
	case len(data) >= 4 && looksLikeZip(data):
		return "zip archive"
	}
	return ""
}

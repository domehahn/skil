package analyzer

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

// buildPycHeader constructs a real, well-formed 16-byte PEP 552 header —
// the same layout verified against an actual Python 3.14 py_compile
// output during development (magic 3627, "\r\n" signature, a
// timestamp-based header whose source-size field matched the real
// source file's byte length exactly).
func buildPycHeader(magic uint16, flags uint32, a, b uint32) []byte {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint16(header[0:2], magic)
	header[2], header[3] = 0x0D, 0x0A
	binary.LittleEndian.PutUint32(header[4:8], flags)
	binary.LittleEndian.PutUint32(header[8:12], a)
	binary.LittleEndian.PutUint32(header[12:16], b)
	return header
}

func TestParsePycHeaderRecognizedVersionTimestampBased(t *testing.T) {
	header := buildPycHeader(3495, 0, 1700000000, 42) // 3.11, timestamp-based, size=42
	parsed, ok := parsePycHeader(header)
	if !ok {
		t.Fatal("expected a valid header")
	}
	if parsed.PythonVersion != "3.11" {
		t.Fatalf("PythonVersion = %q, want 3.11", parsed.PythonVersion)
	}
	if parsed.Invalidation != pycTimestampBased {
		t.Fatalf("Invalidation = %v, want pycTimestampBased", parsed.Invalidation)
	}
	if parsed.SourceSize != 42 {
		t.Fatalf("SourceSize = %d, want 42", parsed.SourceSize)
	}
}

func TestParsePycHeaderUnknownMagicReportsUnknownNotAGuess(t *testing.T) {
	header := buildPycHeader(9999, 0, 0, 0)
	parsed, ok := parsePycHeader(header)
	if !ok {
		t.Fatal("expected a valid header even for an unrecognized magic number")
	}
	if parsed.PythonVersion != "unknown (magic 0x270f)" {
		t.Fatalf("PythonVersion = %q, want the unknown-magic label", parsed.PythonVersion)
	}
}

func TestParsePycHeaderHashBasedModes(t *testing.T) {
	checked := buildPycHeader(3531, 0b11, 0, 0)
	parsed, ok := parsePycHeader(checked)
	if !ok || parsed.Invalidation != pycHashChecked {
		t.Fatalf("expected pycHashChecked: %#v ok=%v", parsed, ok)
	}
	uncheckedHeader := buildPycHeader(3531, 0b01, 0, 0)
	parsed, ok = parsePycHeader(uncheckedHeader)
	if !ok || parsed.Invalidation != pycHashUnchecked {
		t.Fatalf("expected pycHashUnchecked: %#v ok=%v", parsed, ok)
	}
}

func TestParsePycHeaderRejectsMissingSignatureAndShortData(t *testing.T) {
	bad := buildPycHeader(3495, 0, 0, 0)
	bad[2], bad[3] = 0x00, 0x00 // corrupt the \r\n signature
	if _, ok := parsePycHeader(bad); ok {
		t.Fatal("expected a corrupted signature to be rejected")
	}
	if _, ok := parsePycHeader([]byte{0x2b, 0x0e, 0x0d}); ok {
		t.Fatal("expected data shorter than 16 bytes to be rejected")
	}
}

func TestFindPycSourceViaPycache(t *testing.T) {
	files := []skil.File{
		{Path: "pkg/__pycache__/tool.cpython-311.pyc"},
		{Path: "pkg/tool.py", Data: []byte("print(1)\n")},
		{Path: "pkg/other.py", Data: []byte("x\n")},
	}
	source, ok := findPycSource("pkg/__pycache__/tool.cpython-311.pyc", files)
	if !ok || source.Path != "pkg/tool.py" {
		t.Fatalf("expected pkg/tool.py, got %q ok=%v", source.Path, ok)
	}
}

func TestFindPycSourceBareFileSameDirectory(t *testing.T) {
	files := []skil.File{
		{Path: "tool.pyc"},
		{Path: "tool.py", Data: []byte("print(1)\n")},
	}
	source, ok := findPycSource("tool.pyc", files)
	if !ok || source.Path != "tool.py" {
		t.Fatalf("expected tool.py, got %q ok=%v", source.Path, ok)
	}
}

func TestFindPycSourceMissingReturnsFalse(t *testing.T) {
	files := []skil.File{{Path: "pkg/__pycache__/tool.cpython-311.pyc"}}
	if _, ok := findPycSource("pkg/__pycache__/tool.cpython-311.pyc", files); ok {
		t.Fatal("expected no source to be found")
	}
}

func TestPyCAnalyzeFlagsSourceSizeMismatch(t *testing.T) {
	source := []byte("def hello():\n    print('hello')\n") // 33 bytes
	header := buildPycHeader(3495, 0, 1700000000, uint32(len(source)+1))
	artifact := skil.Artifact{Name: "test", Digest: "digest", Files: []skil.File{
		{Path: "tool.pyc", Data: header},
		{Path: "tool.py", Data: source},
	}}
	findings, err := NewPyC().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "SKIL-PYC-SOURCE-MISMATCH" {
		t.Fatalf("expected exactly one SKIL-PYC-SOURCE-MISMATCH finding, got %#v", findings)
	}
}

func TestPyCAnalyzeMatchingSourceSizeProducesNoFinding(t *testing.T) {
	source := []byte("def hello():\n    print('hello')\n")
	header := buildPycHeader(3495, 0, 1700000000, uint32(len(source)))
	artifact := skil.Artifact{Name: "test", Digest: "digest", Files: []skil.File{
		{Path: "tool.pyc", Data: header},
		{Path: "tool.py", Data: source},
	}}
	findings, err := NewPyC().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when the source size matches, got %#v", findings)
	}
}

func TestPyCAnalyzeSkipsHashBasedAndMissingSource(t *testing.T) {
	hashBased := buildPycHeader(3495, 0b11, 0, 0)
	artifact := skil.Artifact{Name: "test", Digest: "digest", Files: []skil.File{
		{Path: "a.pyc", Data: hashBased},                                   // hash-based: no size field to check
		{Path: "b.pyc", Data: buildPycHeader(3495, 0, 1700000000, 999999)}, // no accompanying source at all
	}}
	findings, err := NewPyC().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings: hash-based has no size to check, and b.pyc has no source: %#v", findings)
	}
}

func TestPyCAnalyzeFlagsDangerousSymbolWithNoAccompanyingSource(t *testing.T) {
	artifact := skil.Artifact{Name: "test", Digest: "digest", Files: []skil.File{
		{Path: "helper.pyc", Data: decodePyc(t, realPyc312Danger)},
	}}
	findings, err := NewPyC().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	var found *skil.Finding
	for i := range findings {
		if findings[i].RuleID == "SKIL-PYC-DANGEROUS-SYMBOL" {
			found = &findings[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a SKIL-PYC-DANGEROUS-SYMBOL finding: %#v", findings)
	}
	if found.Severity != skil.SeverityHigh {
		t.Fatalf("severity = %v, want HIGH", found.Severity)
	}
	symbols, ok := found.Evidence["pyc_symbols"].([]string)
	if !ok || !containsString(symbols, "os.system") {
		t.Fatalf("expected os.system in pyc_symbols evidence: %#v", found.Evidence)
	}
	if available, ok := found.Evidence["source_available"].(bool); !ok || available {
		t.Fatalf("expected source_available=false with no accompanying .py: %#v", found.Evidence)
	}
}

func TestPyCAnalyzeDangerousSymbolNotesAccompanyingSource(t *testing.T) {
	artifact := skil.Artifact{Name: "test", Digest: "digest", Files: []skil.File{
		{Path: "danger.pyc", Data: decodePyc(t, realPyc312Danger)},
		{Path: "danger.py", Data: []byte("import os\n\n\ndef run():\n    os.system(\"id\")\n")},
	}}
	findings, err := NewPyC().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID != "SKIL-PYC-DANGEROUS-SYMBOL" {
			continue
		}
		if available, ok := finding.Evidence["source_available"].(bool); !ok || !available {
			t.Fatalf("expected source_available=true: %#v", finding.Evidence)
		}
		return
	}
	t.Fatalf("expected a SKIL-PYC-DANGEROUS-SYMBOL finding: %#v", findings)
}

func TestPyCAnalyzeBenignModuleProducesNoDangerousSymbolFinding(t *testing.T) {
	artifact := skil.Artifact{Name: "test", Digest: "digest", Files: []skil.File{
		{Path: "benign.pyc", Data: decodePyc(t, realPyc312Benign)},
	}}
	findings, err := NewPyC().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PYC-DANGEROUS-SYMBOL" {
			t.Fatalf("did not expect a dangerous-symbol finding for a benign module: %#v", findings)
		}
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestClassifyAnalyzabilityPyCWithSourceIsPartial(t *testing.T) {
	source := []byte("print(1)\n")
	header := buildPycHeader(3495, 0, 1700000000, uint32(len(source)))
	file := skil.File{Path: "tool.pyc", Data: header, Encoding: "binary"}
	all := []skil.File{file, {Path: "tool.py", Data: source}}
	record := classifyAnalyzability(file, all)
	if record.State != skil.AnalyzabilityPartial {
		t.Fatalf("state = %q, want partial: %#v", record.State, record)
	}
	if record.BinaryKind == "" {
		t.Fatal("expected a non-empty BinaryKind for a recognized .pyc")
	}
}

func TestClassifyAnalyzabilityPyCWithoutSourceIsOpaque(t *testing.T) {
	header := buildPycHeader(3495, 0, 1700000000, 42)
	file := skil.File{Path: "tool.pyc", Data: header, Encoding: "binary"}
	record := classifyAnalyzability(file, []skil.File{file})
	if record.State != skil.AnalyzabilityOpaque {
		t.Fatalf("state = %q, want opaque: %#v", record.State, record)
	}
}

package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestDefaultRegistryScanPopulatesAnalyzabilityLedger(t *testing.T) {
	pe := append([]byte{'M', 'Z', 0x90, 0x00}, make([]byte, 32)...)
	artifact := skil.Artifact{Name: "test", Digest: "digest", Files: []skil.File{
		{Path: "SKILL.md", Data: []byte("A safe skill."), Encoding: "utf-8"},
		{Path: "tool.exe", Data: pe, Encoding: "binary", Executable: true},
	}}
	result, err := DefaultRegistry(nil).Scan(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Analyzability) != 2 {
		t.Fatalf("expected one AnalyzabilityRecord per file, got %d: %#v", len(result.Analyzability), result.Analyzability)
	}
	if result.Analyzable.Files != 2 || result.Analyzable.Full != 1 || result.Analyzable.Opaque != 1 {
		t.Fatalf("unexpected analyzability summary: %#v", result.Analyzable)
	}
	if result.Analyzable.Coverage != 0.5 {
		t.Fatalf("Coverage = %v, want 0.5", result.Analyzable.Coverage)
	}
}

func TestClassifyAnalyzabilityUTF8TextIsFull(t *testing.T) {
	file := skil.File{Path: "SKILL.md", Data: []byte("hello"), Encoding: "utf-8"}
	record := classifyAnalyzability(file)
	if record.State != skil.AnalyzabilityFull {
		t.Fatalf("state = %q, want full: %#v", record.State, record)
	}
	if record.Reason != "" {
		t.Fatalf("expected no reason for full analyzability, got %q", record.Reason)
	}
}

func TestClassifyAnalyzabilityRecognizedExecutableIsOpaqueWithBinaryKind(t *testing.T) {
	// "MZ" DOS header prefix, as a real PE would start with.
	data := append([]byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}, make([]byte, 32)...)
	file := skil.File{Path: "tool.exe", Data: data, Encoding: "binary", Executable: true}
	record := classifyAnalyzability(file)
	if record.State != skil.AnalyzabilityOpaque {
		t.Fatalf("state = %q, want opaque", record.State)
	}
	if record.BinaryKind != "Windows PE executable" {
		t.Fatalf("BinaryKind = %q, want %q", record.BinaryKind, "Windows PE executable")
	}
	if record.Reason == "" {
		t.Fatal("expected a non-empty reason for opaque content")
	}
}

func TestClassifyAnalyzabilityUnrecognizedBinaryIsOpaqueWithoutBinaryKind(t *testing.T) {
	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52}
	file := skil.File{Path: "logo.png", Data: data, Encoding: "binary"}
	record := classifyAnalyzability(file)
	if record.State != skil.AnalyzabilityOpaque {
		t.Fatalf("state = %q, want opaque", record.State)
	}
	if record.BinaryKind != "" {
		t.Fatalf("BinaryKind = %q, want empty for an unrecognized binary format", record.BinaryKind)
	}
}

func TestSummarizeAnalyzabilityComputesBlendedCoverage(t *testing.T) {
	records := []skil.AnalyzabilityRecord{
		{State: skil.AnalyzabilityFull},
		{State: skil.AnalyzabilityFull},
		{State: skil.AnalyzabilityPartial},
		{State: skil.AnalyzabilityOpaque},
	}
	summary := summarizeAnalyzability(records)
	if summary.Files != 4 || summary.Full != 2 || summary.Partial != 1 || summary.Opaque != 1 {
		t.Fatalf("unexpected summary counts: %#v", summary)
	}
	want := (2.0 + 0.5*1.0) / 4.0
	if summary.Coverage != want {
		t.Fatalf("Coverage = %v, want %v", summary.Coverage, want)
	}
}

func TestSummarizeAnalyzabilityEmptyArtifactIsFullCoverage(t *testing.T) {
	summary := summarizeAnalyzability(nil)
	if summary.Coverage != 1 || summary.Files != 0 {
		t.Fatalf("unexpected summary for empty artifact: %#v", summary)
	}
}

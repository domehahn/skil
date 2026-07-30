package analyzer

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

// buildProto2PickleGlobal constructs a minimal valid pickle byte stream
// (PROTO 2, GLOBAL module/name, STOP) using real pickle opcodes, so tests
// exercise the actual opcode parser rather than asserting against a
// hand-picked byte blob.
func buildProto2PickleGlobal(module, name string) []byte {
	var b []byte
	b = append(b, 0x80, 0x02) // PROTO 2
	b = append(b, 'c')        // GLOBAL
	b = append(b, module...)
	b = append(b, '\n')
	b = append(b, name...)
	b = append(b, '\n')
	b = append(b, '.') // STOP
	return b
}

// buildProto4PickleGlobal constructs a minimal PROTO 4 pickle stream using
// SHORT_BINUNICODE + STACK_GLOBAL, matching the opcode sequence real
// PyTorch/protocol-4 pickles emit for a class reference.
func buildProto4PickleGlobal(module, name string) []byte {
	var b []byte
	b = append(b, 0x80, 0x04) // PROTO 4
	push := func(s string) {
		b = append(b, 0x8c, byte(len(s)))
		b = append(b, s...)
	}
	push(module)
	push(name)
	b = append(b, 0x93) // STACK_GLOBAL
	b = append(b, '.')  // STOP
	return b
}

func buildBenignPickle() []byte {
	// PROTO 2, EMPTY_DICT, STOP — a benign object with no GLOBAL reference.
	return []byte{0x80, 0x02, '}', '.'}
}

func TestPickleScannerExtractsGlobalProtocol0Through2(t *testing.T) {
	globals := scanPickleOpcodes(buildProto2PickleGlobal("os", "system"))
	if len(globals) != 1 || globals[0].Module != "os" || globals[0].Name != "system" {
		t.Fatalf("expected os.system: %#v", globals)
	}
}

func TestPickleScannerExtractsStackGlobalProtocol4(t *testing.T) {
	globals := scanPickleOpcodes(buildProto4PickleGlobal("os", "system"))
	if len(globals) != 1 || globals[0].Module != "os" || globals[0].Name != "system" {
		t.Fatalf("expected os.system via STACK_GLOBAL: %#v", globals)
	}
}

func TestPickleScannerBenignObjectHasNoGlobals(t *testing.T) {
	globals := scanPickleOpcodes(buildBenignPickle())
	if len(globals) != 0 {
		t.Fatalf("expected no globals in an empty dict: %#v", globals)
	}
}

func modelFindings(t *testing.T, path string, data []byte) []skil.Finding {
	t.Helper()
	artifact := skil.Artifact{Files: []skil.File{{Path: path, Data: data}}}
	findings, err := NewModelArtifact().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestDangerousPickleGlobalIsDetected(t *testing.T) {
	findings := modelFindings(t, "model.pkl", buildProto2PickleGlobal("os", "system"))
	if !hasRule(findings, "SKIL-MODEL-PICKLE-001") {
		t.Fatalf("expected dangerous pickle global to be detected: %#v", findings)
	}
}

func TestBenignPickleHasNoDangerousGlobalFinding(t *testing.T) {
	findings := modelFindings(t, "model.pkl", buildBenignPickle())
	if hasRule(findings, "SKIL-MODEL-PICKLE-001") {
		t.Fatalf("a benign pickle object should not fire the dangerous-global rule: %#v", findings)
	}
	if !hasRule(findings, "SKIL-MODEL-FORMAT-POLICY") {
		t.Fatalf("pickle format itself should still produce a format-policy advisory: %#v", findings)
	}
}

func TestBenignNumpyTorchGlobalsAreNotFlaggedDangerous(t *testing.T) {
	findings := modelFindings(t, "model.pkl", buildProto2PickleGlobal("collections", "OrderedDict"))
	if hasRule(findings, "SKIL-MODEL-PICKLE-001") {
		t.Fatalf("a benign collections.OrderedDict reference should not fire: %#v", findings)
	}
}

func TestSafetensorsFormatHasNoFinding(t *testing.T) {
	findings := modelFindings(t, "model.safetensors", []byte("not parsed, format policy only"))
	if len(findings) != 0 {
		t.Fatalf("safetensors is the preferred format and should not produce any finding: %#v", findings)
	}
}

func TestZipWrappedTorchCheckpointDangerousGlobalIsDetected(t *testing.T) {
	// PyTorch has saved checkpoints as a zip container with a "*/data.pkl"
	// member since 1.6; this must be scanned the same as a raw pickle
	// stream without ever calling torch.load or otherwise deserializing.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("archive/data.pkl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(buildProto2PickleGlobal("os", "system")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	findings := modelFindings(t, "checkpoint.pt", buf.Bytes())
	if !hasRule(findings, "SKIL-MODEL-PICKLE-001") {
		t.Fatalf("expected the dangerous global inside the zip-wrapped checkpoint to be detected: %#v", findings)
	}
}

func TestTrustRemoteCodeIsDetected(t *testing.T) {
	findings := modelFindings(t, "load.py", []byte(`model = AutoModel.from_pretrained("org/model", trust_remote_code=True)`+"\n"))
	if !hasRule(findings, "SKIL-MODEL-REMOTE-CODE") {
		t.Fatalf("expected trust_remote_code=True to be detected: %#v", findings)
	}
}

func TestTrustRemoteCodeFalseIsSafe(t *testing.T) {
	findings := modelFindings(t, "load.py", []byte(`model = AutoModel.from_pretrained("org/model", trust_remote_code=False)`+"\n"))
	if hasRule(findings, "SKIL-MODEL-REMOTE-CODE") {
		t.Fatalf("trust_remote_code=False should not fire: %#v", findings)
	}
}

func TestCustomModelLoaderFileIsDetected(t *testing.T) {
	findings := modelFindings(t, "modeling_custom.py", []byte("class CustomModel:\n    pass\n"))
	if !hasRule(findings, "SKIL-MODEL-CUSTOM-LOADER") {
		t.Fatalf("expected a custom modeling_*.py loader file to be detected: %#v", findings)
	}
}

func TestOrdinaryPythonFileIsNotFlaggedAsCustomLoader(t *testing.T) {
	findings := modelFindings(t, "utils.py", []byte("def helper():\n    pass\n"))
	if hasRule(findings, "SKIL-MODEL-CUSTOM-LOADER") {
		t.Fatalf("an ordinary Python file should not be flagged as a custom model loader: %#v", findings)
	}
}

func TestKerasLambdaLayerIsDetected(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("config.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"layers":[{"class_name":"Lambda","config":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	findings := modelFindings(t, "model.keras", buf.Bytes())
	if !hasRule(findings, "SKIL-MODEL-KERAS-001") {
		t.Fatalf("expected a Lambda layer in the Keras config to be detected: %#v", findings)
	}
}

func TestKerasWithoutLambdaIsSafe(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("config.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"layers":[{"class_name":"Dense","config":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	findings := modelFindings(t, "model.keras", buf.Bytes())
	if hasRule(findings, "SKIL-MODEL-KERAS-001") {
		t.Fatalf("an ordinary Dense layer should not fire the Lambda-layer rule: %#v", findings)
	}
}

func TestUnpinnedModelReferenceIsDetected(t *testing.T) {
	content := `m = AutoModel.from_pretrained("acme-org/widget-model")` + "\n"
	findings := modelFindings(t, "load.py", []byte(content))
	if !hasRule(findings, "SKIL-MODEL-UNPINNED") {
		t.Fatalf("expected an unpinned model reference to be detected: %#v", findings)
	}
}

func TestPinnedModelReferenceIsSafe(t *testing.T) {
	content := `m = AutoModel.from_pretrained("acme-org/widget-model", revision="a1b2c3d4")` + "\n"
	findings := modelFindings(t, "load.py", []byte(content))
	if hasRule(findings, "SKIL-MODEL-UNPINNED") || hasRule(findings, "SKIL-MODEL-MUTABLE-REF") {
		t.Fatalf("a model pinned to a commit hash should not fire: %#v", findings)
	}
}

func TestMutableModelRevisionIsDetected(t *testing.T) {
	content := `m = AutoModel.from_pretrained("meta-llama/Llama-3", revision="main")` + "\n"
	findings := modelFindings(t, "load.py", []byte(content))
	if !hasRule(findings, "SKIL-MODEL-MUTABLE-REF") {
		t.Fatalf("expected a mutable branch-name revision to be detected: %#v", findings)
	}
}

func TestModelPublisherTyposquatIsDetected(t *testing.T) {
	content := `m = AutoModel.from_pretrained("0penai/gpt-foo", revision="a1b2c3d4")` + "\n"
	findings := modelFindings(t, "load.py", []byte(content))
	if !hasRule(findings, "SKIL-MODEL-TYPOSQUAT") {
		t.Fatalf("expected a typosquatted publisher org to be detected: %#v", findings)
	}
}

func TestKnownPublisherIsNotFlaggedAsTyposquat(t *testing.T) {
	content := `m = AutoModel.from_pretrained("openai/gpt-foo", revision="a1b2c3d4")` + "\n"
	findings := modelFindings(t, "load.py", []byte(content))
	if hasRule(findings, "SKIL-MODEL-TYPOSQUAT") {
		t.Fatalf("the real openai org should not be flagged as a typosquat of itself: %#v", findings)
	}
}

package analyzer

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func assetFindings(t *testing.T, path string, data []byte) []skil.Finding {
	t.Helper()
	artifact := skil.Artifact{Files: []skil.File{{Path: path, Data: data}}}
	findings, err := NewAsset().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestSVGScriptTagIsDetected(t *testing.T) {
	findings := assetFindings(t, "icon.svg", []byte(`<svg><script>alert(document.cookie)</script></svg>`))
	if !hasRule(findings, "SKIL-ASSET-SVG-SCRIPT") {
		t.Fatalf("expected an SVG <script> tag to be detected: %#v", findings)
	}
}

func TestSVGEventHandlerIsDetected(t *testing.T) {
	findings := assetFindings(t, "icon.svg", []byte(`<svg onload="evil()"><circle/></svg>`))
	if !hasRule(findings, "SKIL-ASSET-SVG-SCRIPT") {
		t.Fatalf("expected an SVG onload handler to be detected: %#v", findings)
	}
}

func TestOrdinarySVGIsSafe(t *testing.T) {
	findings := assetFindings(t, "icon.svg", []byte(`<svg><circle cx="50" cy="50" r="40"/></svg>`))
	if hasRule(findings, "SKIL-ASSET-SVG-SCRIPT") {
		t.Fatalf("an ordinary SVG shape should not fire: %#v", findings)
	}
}

func TestPDFJavaScriptIsDetected(t *testing.T) {
	findings := assetFindings(t, "doc.pdf", []byte("%PDF-1.4\n<< /S /JavaScript /JS (app.alert(1)) >>\n"))
	if !hasRule(findings, "SKIL-ASSET-PDF-JAVASCRIPT") {
		t.Fatalf("expected embedded PDF JavaScript to be detected: %#v", findings)
	}
}

func TestOrdinaryPDFIsSafe(t *testing.T) {
	findings := assetFindings(t, "doc.pdf", []byte("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n"))
	if hasRule(findings, "SKIL-ASSET-PDF-JAVASCRIPT") {
		t.Fatalf("an ordinary PDF without embedded JavaScript should not fire: %#v", findings)
	}
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOfficeMacroIsDetected(t *testing.T) {
	data := buildZip(t, map[string]string{"word/vbaProject.bin": "fake macro bytes", "[Content_Types].xml": "<Types/>"})
	findings := assetFindings(t, "report.docx", data)
	if !hasRule(findings, "SKIL-ASSET-OFFICE-MACRO") {
		t.Fatalf("expected an embedded VBA macro project to be detected: %#v", findings)
	}
}

func TestMacroFreeOfficeDocumentIsSafe(t *testing.T) {
	data := buildZip(t, map[string]string{"word/document.xml": "<document/>", "[Content_Types].xml": "<Types/>"})
	findings := assetFindings(t, "report.docx", data)
	if hasRule(findings, "SKIL-ASSET-OFFICE-MACRO") {
		t.Fatalf("a macro-free Office document should not fire: %#v", findings)
	}
}

func TestDisguisedPEExecutableIsDetected(t *testing.T) {
	data := append([]byte{'M', 'Z'}, bytes.Repeat([]byte{0x90}, 30)...)
	findings := assetFindings(t, "notes.txt", data)
	if !hasRule(findings, "SKIL-ASSET-FILE-TYPE-MISMATCH") {
		t.Fatalf("expected a PE executable disguised as .txt to be detected: %#v", findings)
	}
}

func TestDisguisedELFExecutableIsDetected(t *testing.T) {
	data := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x00}, 30)...)
	findings := assetFindings(t, "config.conf", data)
	if !hasRule(findings, "SKIL-ASSET-FILE-TYPE-MISMATCH") {
		t.Fatalf("expected an ELF executable disguised as .conf to be detected: %#v", findings)
	}
}

func TestOrdinaryTextFileIsSafe(t *testing.T) {
	findings := assetFindings(t, "notes.txt", []byte("This is a plain text note.\n"))
	if hasRule(findings, "SKIL-ASSET-FILE-TYPE-MISMATCH") {
		t.Fatalf("an ordinary text file should not fire: %#v", findings)
	}
}

func buildWasmWithImport() []byte {
	// Build a minimal valid WASM binary with an import section (ID 2).
	var b []byte
	b = append(b, 0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00) // header
	// Type section (ID 1) needed so the import can reference a type index.
	typeContent := []byte{0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f} // func(i32,i32)->i32
	typeSize := uint64(len(typeContent))
	b = append(b, 0x01) // section 1
	b = append(b, encodeULEB128(typeSize)...)
	b = append(b, typeContent...)
	// Import section (ID 2): one import of kind "func".
	mod := "wasi_snapshot_preview1"
	name := "fd_write"
	importContent := []byte{}
	importContent = append(importContent, encodeULEB128(1)...)                 // 1 import
	importContent = append(importContent, encodeULEB128(uint64(len(mod)))...)  // module length
	importContent = append(importContent, mod...)                              // module
	importContent = append(importContent, encodeULEB128(uint64(len(name)))...) // name length
	importContent = append(importContent, name...)                             // name
	importContent = append(importContent, 0x00)                                // func kind
	importContent = append(importContent, encodeULEB128(0)...)                 // type index 0
	b = append(b, 0x02)                                                        // section 2
	b = append(b, encodeULEB128(uint64(len(importContent)))...)
	b = append(b, importContent...)
	return b
}

func encodeULEB128(v uint64) []byte {
	var b []byte
	for {
		buf := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			buf |= 0x80
		}
		b = append(b, buf)
		if v == 0 {
			return b
		}
	}
}

func TestWasmWithImportSectionIsDetected(t *testing.T) {
	data := buildWasmWithImport()
	findings := assetFindings(t, "module.wasm", data)
	if !hasRule(findings, "SKIL-ASSET-WASM-IMPORT") {
		t.Fatalf("expected a WASM binary with import section to be detected: %#v", findings)
	}
}

func TestOrdinaryWasmWithoutImportIsSafe(t *testing.T) {
	data := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f}
	findings := assetFindings(t, "module.wasm", data)
	if hasRule(findings, "SKIL-ASSET-WASM-IMPORT") {
		t.Fatalf("a WASM binary without import section should not fire: %#v", findings)
	}
}

func TestActualExecutableWithExecutableExtensionIsNotFlaggedAsMismatch(t *testing.T) {
	// A .bin/.exe file that is genuinely a PE/ELF binary is not a
	// mismatch — it is what its extension says it is. The property this
	// rule targets is disguise, not "any binary present".
	data := append([]byte{'M', 'Z'}, bytes.Repeat([]byte{0x90}, 30)...)
	findings := assetFindings(t, "tool.exe", data)
	if hasRule(findings, "SKIL-ASSET-FILE-TYPE-MISMATCH") {
		t.Fatalf("a .exe file that is genuinely a PE executable should not fire the mismatch rule: %#v", findings)
	}
}

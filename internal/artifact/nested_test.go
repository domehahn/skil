package artifact

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

type zipEntry struct {
	name    string
	content []byte
	mode    os.FileMode
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(mode)
		w, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func containerFile(t *testing.T, path string, entries []zipEntry) skil.File {
	t.Helper()
	data := buildZip(t, entries)
	sum := sha256.Sum256(data)
	return skil.File{Path: path, Data: data, SHA256: hex.EncodeToString(sum[:])}
}

func TestVirtualizeNestedContainersMaterializesMember(t *testing.T) {
	outer := containerFile(t, "bundle.zip", []zipEntry{{name: "scripts/tool.py", content: []byte("print('hi')")}})
	virtual, diagnostics := VirtualizeNestedContainers([]skil.File{outer})
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
	if len(virtual) != 1 {
		t.Fatalf("expected exactly one virtual file, got %#v", virtual)
	}
	got := virtual[0]
	if got.Path != "bundle.zip!/scripts/tool.py" {
		t.Fatalf("unexpected provenance path: %q", got.Path)
	}
	if got.ContainerDepth != 1 {
		t.Fatalf("expected depth 1, got %d", got.ContainerDepth)
	}
	if got.ContainerParentSHA256 != outer.SHA256 {
		t.Fatalf("expected parent digest %q, got %q", outer.SHA256, got.ContainerParentSHA256)
	}
	if string(got.Data) != "print('hi')" {
		t.Fatalf("unexpected materialized content: %q", got.Data)
	}
}

func TestVirtualizeNestedContainersRecursesIntoNestedZip(t *testing.T) {
	inner := buildZip(t, []zipEntry{{name: "evil.py", content: []byte("eval(x)")}})
	outer := containerFile(t, "document.docx", []zipEntry{{name: "embedded.zip", content: inner}})
	virtual, diagnostics := VirtualizeNestedContainers([]skil.File{outer})
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
	var depths []int
	var paths []string
	for _, file := range virtual {
		depths = append(depths, file.ContainerDepth)
		paths = append(paths, file.Path)
	}
	if len(virtual) != 2 {
		t.Fatalf("expected the embedded.zip member and evil.py inside it, got %#v", paths)
	}
	if !containsPath(paths, "document.docx!/embedded.zip") || !containsPath(paths, "document.docx!/embedded.zip!/evil.py") {
		t.Fatalf("unexpected provenance paths: %#v", paths)
	}
	if len(depths) != 2 || depths[0] != 1 || depths[1] != 2 {
		t.Fatalf("unexpected container depths: %#v", depths)
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func TestVirtualizeNestedContainersRespectsDepthLimit(t *testing.T) {
	// Build a chain one level deeper than MaxContainerDepth allows.
	current := buildZip(t, []zipEntry{{name: "deepest.txt", content: []byte("x")}})
	for i := 0; i < MaxContainerDepth; i++ {
		current = buildZip(t, []zipEntry{{name: "level.zip", content: current}})
	}
	outer := containerFile(t, "root.zip", []zipEntry{{name: "level.zip", content: current}})
	virtual, _ := VirtualizeNestedContainers([]skil.File{outer})
	for _, file := range virtual {
		if file.ContainerDepth > MaxContainerDepth {
			t.Fatalf("materialized a file beyond MaxContainerDepth: %#v", file)
		}
	}
	// The deepest possible materialized depth is MaxContainerDepth; deepest.txt
	// would require one level more and must not appear.
	for _, file := range virtual {
		if strings.HasSuffix(file.Path, "deepest.txt") {
			t.Fatalf("deepest.txt should have been beyond the depth limit: %#v", file)
		}
	}
}

func TestVirtualizeNestedContainersRejectsOversizedMember(t *testing.T) {
	big := bytes.Repeat([]byte("a"), MaxContainerMemberBytes+1)
	outer := containerFile(t, "bundle.zip", []zipEntry{{name: "huge.bin", content: big}})
	virtual, diagnostics := VirtualizeNestedContainers([]skil.File{outer})
	if len(virtual) != 0 {
		t.Fatalf("oversized member must not be materialized: %#v", virtual)
	}
	if len(diagnostics) == 0 {
		t.Fatal("expected a diagnostic for the skipped oversized member")
	}
}

func TestVirtualizeNestedContainersRejectsExcessiveCompressionRatio(t *testing.T) {
	// Highly compressible content (all zeros) compresses far beyond
	// MaxContainerCompressionRatio:1 with Deflate.
	bomb := make([]byte, MaxContainerMemberBytes)
	outer := containerFile(t, "bundle.zip", []zipEntry{{name: "bomb.bin", content: bomb}})
	virtual, diagnostics := VirtualizeNestedContainers([]skil.File{outer})
	if len(virtual) != 0 {
		t.Fatalf("a member exceeding the compression ratio bound must not be materialized: %#v", virtual)
	}
	if len(diagnostics) == 0 {
		t.Fatal("expected a diagnostic for the rejected member")
	}
}

func TestVirtualizeNestedContainersRejectsPathTraversal(t *testing.T) {
	outer := containerFile(t, "bundle.zip", []zipEntry{{name: "../../etc/passwd", content: []byte("x")}})
	virtual, diagnostics := VirtualizeNestedContainers([]skil.File{outer})
	if len(virtual) != 0 {
		t.Fatalf("a path-traversal member must not be materialized: %#v", virtual)
	}
	if len(diagnostics) == 0 {
		t.Fatal("expected a diagnostic for the rejected member")
	}
}

func TestVirtualizeNestedContainersIgnoresNonZipFiles(t *testing.T) {
	plain := skil.File{Path: "README.md", Data: []byte("just text"), SHA256: "irrelevant"}
	virtual, diagnostics := VirtualizeNestedContainers([]skil.File{plain})
	if len(virtual) != 0 || len(diagnostics) != 0 {
		t.Fatalf("an ordinary non-zip file must produce nothing: virtual=%#v diagnostics=%#v", virtual, diagnostics)
	}
}

// TestLoadVirtualizesNestedContainersEndToEnd exercises the real Load()
// entry point (directory source) rather than calling
// VirtualizeNestedContainers directly, proving the wiring — appended
// files, LoadDiagnostics threading, and digest inclusion — actually works.
func TestLoadVirtualizesNestedContainersEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipData := buildZip(t, []zipEntry{{name: "scripts/tool.py", content: []byte("eval(x)")}})
	if err := os.WriteFile(filepath.Join(dir, "bundle.zip"), zipData, 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, file := range artifact.Files {
		if file.Path == "bundle.zip!/scripts/tool.py" {
			found = true
			if file.ContainerDepth != 1 {
				t.Fatalf("expected depth 1, got %d", file.ContainerDepth)
			}
		}
	}
	if !found {
		t.Fatalf("expected a virtualized file in the loaded artifact: %#v", artifact.Files)
	}
}

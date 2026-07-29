package artifact

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/pkg/skil"
)

func TestLoadDirectoryDigestIsStable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatal("digest is not stable")
	}
}

func TestArchiveSkillRootNormalizationMatchesDirectory(t *testing.T) {
	root := t.TempDir()
	skillDir := filepath.Join(root, "sample")
	if err := os.MkdirAll(filepath.Join(skillDir, ".skil"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"SKILL.md":                  "# sample",
		".skil/mcp-tools.lock.json": `{"version":1,"tools":{"weather":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`,
		"mcp.json":                  `{"tools":[{"name":"weather","description":"weather"}]}`,
	}
	for name, data := range files {
		path := filepath.Join(skillDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	zipPath := filepath.Join(root, "sample.zip")
	writeTestZIP(t, zipPath, "sample", files)
	tgzPath := filepath.Join(root, "sample.tgz")
	writeTestTGZ(t, tgzPath, "sample", files)

	directory, err := Load(skillDir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, archivePath := range []string{zipPath, tgzPath} {
		archive, err := Load(archivePath, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if archive.Digest != directory.Digest {
			t.Fatalf("%s content digest differs after root normalization", archivePath)
		}
		if archive.Files[0].Path == "sample/SKILL.md" {
			t.Fatalf("%s retained the packaging root", archivePath)
		}
		assertMCPMetadataLockApplied(t, archive)
	}
	assertMCPMetadataLockApplied(t, directory)
}

func assertMCPMetadataLockApplied(t *testing.T, artifact skil.Artifact) {
	t.Helper()
	findings, err := analyzer.NewMCP().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-MCP-005" {
			return
		}
	}
	t.Fatalf("canonical MCP metadata lock was not applied: %#v", findings)
}

func writeTestZIP(t *testing.T, path, root string, files map[string]string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, data := range files {
		member, err := writer.Create(root + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTestTGZ(t *testing.T, path, root string, files map[string]string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	writer := tar.NewWriter(gzipWriter)
	for name, data := range files {
		header := &tar.Header{Name: root + "/" + name, Mode: 0o600, Size: int64(len(data))}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestZIPTraversalRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, _ := z.Create("../escape")
	_, _ = w.Write([]byte("bad"))
	_ = z.Close()
	_ = f.Close()
	if _, err := Load(path, Options{}); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestPackageAndContentDigestsAreDistinctIdentities(t *testing.T) {
	makeArchive := func(path, comment string) {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		writer := zip.NewWriter(f)
		if err := writer.SetComment(comment); err != nil {
			t.Fatal(err)
		}
		member, err := writer.Create("SKILL.md")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write([]byte("same content")); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	firstPath, secondPath := filepath.Join(dir, "first.zip"), filepath.Join(dir, "second.zip")
	makeArchive(firstPath, "transport one")
	makeArchive(secondPath, "transport two")
	first, err := Load(firstPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(secondPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatal("identical unpacked content must have the same manifest digest")
	}
	if first.PackageDigest == second.PackageDigest || first.PackageDigest == "" {
		t.Fatal("different archive bytes must have different package digests")
	}
}

func TestLoadDirectoryHonorsExplicitSkilIgnore(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".skilignore"), []byte("bin/**\n*.sarif\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "oversized"), make([]byte, MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.sarif"), []byte("generated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Files) != 2 || artifact.Files[0].Path != ".skilignore" || artifact.Files[1].Path != "SKILL.md" {
		t.Fatalf("unexpected files after ignore processing: %#v", artifact.Files)
	}
}

func TestSkilIgnoreRejectsUnsafeOrAmbiguousPatterns(t *testing.T) {
	for _, pattern := range []string{"!keep.txt\n", "../outside\n"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".skilignore"), []byte(pattern), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, Options{}); err == nil {
			t.Fatalf("expected pattern %q to be rejected", pattern)
		}
	}
}

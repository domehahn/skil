package artifact

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
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

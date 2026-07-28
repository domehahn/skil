package packagecheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/pkg/skil"
)

func TestDeterministicArchiveRoundTripAndAtomicInstall(t *testing.T) {
	item := skil.Artifact{Digest: "digest", Files: []skil.File{{Path: "SKILL.md", Data: []byte("hello"), SHA256: "x"}}}
	first, second := filepath.Join(t.TempDir(), "first.tgz"), filepath.Join(t.TempDir(), "second.tgz")
	if err := WriteTGZ(first, item); err != nil {
		t.Fatal(err)
	}
	if err := WriteTGZ(second, item); err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("canonical archives must be byte-for-byte deterministic")
	}
	loaded, err := artifact.Load(first, artifact.Options{})
	if err != nil || len(loaded.Files) != 1 {
		t.Fatalf("round trip failed: %v %#v", err, loaded)
	}
	destination := filepath.Join(t.TempDir(), "installed")
	if err := Install(destination, loaded); err != nil {
		t.Fatal(err)
	}
	if err := Install(destination, loaded); err == nil {
		t.Fatal("installer must not overwrite an existing target")
	}
}

func TestArchiveAndInstallRejectTraversalInConstructedArtifacts(t *testing.T) {
	item := skil.Artifact{Files: []skil.File{{Path: "../escape", Data: []byte("bad")}}}
	if err := WriteTGZ(filepath.Join(t.TempDir(), "bad.tgz"), item); err == nil {
		t.Fatal("expected archive traversal rejection")
	}
	if err := Install(filepath.Join(t.TempDir(), "installed"), item); err == nil {
		t.Fatal("expected install traversal rejection")
	}
}

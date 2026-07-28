package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLockfileRoundTripAndVerify(t *testing.T) {
	entry := Entry{Name: "reviewer", Version: "1.0.0", Source: "reviewer.tgz",
		PackageSHA256: strings.Repeat("a", 64), ContentSHA256: strings.Repeat("b", 64),
		Signature: "reviewer.sig.json", Provenance: "reviewer.provenance.json"}
	lock := Put(File{Version: 1}, entry)
	path := filepath.Join(t.TempDir(), "agent-skills.lock")
	if err := Write(path, lock); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(loaded, entry.Name, entry.Version, entry.Source, entry.PackageSHA256, entry.ContentSHA256); err != nil {
		t.Fatal(err)
	}
	if err := Verify(loaded, entry.Name, entry.Version, entry.Source, strings.Repeat("c", 64), entry.ContentSHA256); err == nil {
		t.Fatal("expected digest mismatch")
	}
}

func TestPortableLockAliasesNormalizeWithoutDigestConflation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portable.lock")
	data := []byte(`version: 1
skills:
  - name: sample
    version: 1.0.0
    artifact: registry.example/sample-1.0.0.tgz
    sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    signature: sample.sig
    provenance: sample.provenance
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	entry := lock.Skills[0]
	if entry.Source != "registry.example/sample-1.0.0.tgz" || entry.PackageSHA256 != strings.Repeat("a", 64) ||
		entry.ContentSHA256 != "" || entry.Artifact != "" || entry.SHA256 != "" {
		t.Fatalf("portable entry was not normalized safely: %#v", entry)
	}
	if err := Verify(lock, entry.Name, entry.Version, entry.Source, entry.PackageSHA256, strings.Repeat("b", 64)); err != nil {
		t.Fatalf("portable package digest should verify without inventing a content digest: %v", err)
	}
}

func TestFindPutAndRemoveLifecycle(t *testing.T) {
	lock := File{Version: 1}
	entry := Entry{Name: "demo", Version: "1.0.0"}
	lock = Put(lock, entry)
	if got, ok := Find(lock, "demo"); !ok || got.Version != "1.0.0" {
		t.Fatalf("entry not found: %#v %v", got, ok)
	}
	lock = Put(lock, Entry{Name: "demo", Version: "2.0.0"})
	if len(lock.Skills) != 1 || lock.Skills[0].Version != "2.0.0" {
		t.Fatalf("put did not replace: %#v", lock)
	}
	lock = Remove(lock, "demo")
	if len(lock.Skills) != 0 {
		t.Fatalf("remove failed: %#v", lock)
	}
}

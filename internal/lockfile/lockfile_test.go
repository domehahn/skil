package lockfile

import (
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

package collection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverDeterministicSkillRoots(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"b", "a"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("# test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 || filepath.Base(roots[0]) != "a" || filepath.Base(roots[1]) != "b" {
		t.Fatalf("unexpected roots: %#v", roots)
	}
}

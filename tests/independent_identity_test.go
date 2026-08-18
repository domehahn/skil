package tests

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicSourcesUseIndependentProductIdentity(t *testing.T) {
	root := filepath.Clean("..")
	forbidden := []string{
		strings.ToLower("Skill" + "Spector"),
		"68 " + "patterns",
		"17 " + "categories",
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".agents", ".github", ".agentic", ".codex":
				return filepath.SkipDir
			}
			if strings.Contains(path, "docs/adr") {
				return filepath.SkipDir
			}
			// benchmark/ is the one deliberate exception to this repository's
			// no-third-party-branding policy: a vendor-neutral benchmark that
			// won't say which tool got which score isn't a benchmark. See
			// benchmark/README.md's "Why this is named differently" section.
			if strings.HasPrefix(path, root+"/benchmark") {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".go", ".md", ".json", ".yaml", ".yml":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(data))
		for _, value := range forbidden {
			if strings.Contains(lower, value) {
				t.Errorf("%s contains prohibited third-party compatibility branding %q", path, value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

package evidence

import (
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestPersistReportsFilesystemFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "attestation.json")
	if err := Persist(path, skil.Attestation{Version: 1}); err == nil {
		t.Fatal("persistence failure was swallowed")
	}
}

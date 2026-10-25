package continuous

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/pkg/skil"
)

func TestEvaluateInvalidatesRuntimePinOnDigestDrift(t *testing.T) {
	first := Evaluate(nil, "skill", skil.ScanResult{Artifact: skil.Artifact{Digest: "a"}}, policy.Result{Decision: "ALLOW"}, time.Unix(1, 0))
	second := Evaluate(&first, "skill", skil.ScanResult{Artifact: skil.Artifact{Digest: "b"}}, policy.Result{Decision: "ALLOW"}, time.Unix(2, 0))
	if first.RuntimePinValid || !second.Changed || second.RuntimePinValid || !second.AttestationRefreshRequired {
		t.Fatalf("unexpected drift state: %#v", second)
	}
}

func TestStateSaveLoadIsAtomicAndVersioned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := Evaluate(nil, "skill", skil.ScanResult{Artifact: skil.Artifact{Digest: "a"}}, policy.Result{Decision: "ALLOW"}, time.Unix(1, 0))
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ArtifactDigest != want.ArtifactDigest || got.SchemaVersion != SchemaVersion {
		t.Fatalf("state mismatch: %#v", got)
	}
}

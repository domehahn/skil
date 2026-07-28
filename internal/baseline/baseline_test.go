package baseline

import (
	"testing"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func TestSuppressionRemainsVisibleAndExpires(t *testing.T) {
	finding := skil.Finding{Fingerprint: "fp", RuleID: "R", Location: skil.Location{File: "a"}}
	file := Create([]skil.Finding{finding}, "reviewer", "accepted")
	applied := Apply([]skil.Finding{finding}, file, time.Now())
	if !applied[0].Suppressed {
		t.Fatal("expected visible suppression")
	}
	past := time.Now().Add(-time.Hour)
	file.Entries[0].ExpiresAt = &past
	applied = Apply([]skil.Finding{finding}, file, time.Now())
	if applied[0].Suppressed {
		t.Fatal("expired suppression applied")
	}
}

package baseline

import (
	"os"
	"path/filepath"
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

func TestGlobRuleRequiresAllSelectorsAndRecordsReason(t *testing.T) {
	findings := []skil.Finding{
		{RuleID: "SKIL-PI-001", Message: "override", Location: skil.Location{File: "nested/SKILL.md"},
			Evidence: map[string]any{"match": "ignore prior instructions"}},
		{RuleID: "SKIL-PI-001", Message: "override", Location: skil.Location{File: "other.txt"}},
	}
	file := File{Version: 2, Rules: []Rule{{
		RuleID: "SKIL-PI-*", Path: "*/SKILL.md", Message: "*prior*", Reason: "reviewed example",
	}}}
	applied := Apply(findings, file, time.Now())
	if !applied[0].Suppressed || applied[0].SuppressionReason != "reviewed example" {
		t.Fatalf("glob rule did not apply with audit reason: %#v", applied[0])
	}
	if applied[1].Suppressed {
		t.Fatal("partially matching finding was suppressed")
	}
}

func TestLoadRejectsBroadReasonlessRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nrules:\n  - rule_id: '*'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid broad baseline rule to fail closed")
	}
}

func TestVersionTwoExactEntriesAreBoundToArtifactAndScanner(t *testing.T) {
	finding := skil.Finding{Fingerprint: "fp", RuleID: "R", Location: skil.Location{File: "a"}}
	scan := skil.ScanResult{Artifact: skil.Artifact{Digest: "artifact"}, Findings: []skil.Finding{finding}}
	file := CreateForScan(scan, "reviewer", "accepted")
	if !ApplyForArtifact([]skil.Finding{finding}, file, time.Now(), "artifact")[0].Suppressed {
		t.Fatal("matching evidence-bound baseline was not applied")
	}
	if ApplyForArtifact([]skil.Finding{finding}, file, time.Now(), "changed")[0].Suppressed {
		t.Fatal("exact baseline survived an artifact change")
	}
	file.ScannerVersion = "different"
	if ApplyForArtifact([]skil.Finding{finding}, file, time.Now(), "artifact")[0].Suppressed {
		t.Fatal("exact baseline survived a scanner version change")
	}
}

package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func completeScan() skil.ScanResult {
	return skil.ScanResult{
		Artifact:     skil.Artifact{Name: "s", Digest: "sha256:aa"},
		Completeness: skil.InspectionSummary{Total: 2, Applicable: 2, Completed: 2, Completeness: 1},
		Findings: []skil.Finding{
			{RuleID: "R2", Fingerprint: "f2", Message: "b", Location: skil.Location{File: "b.md", StartLine: 3, EndLine: 3}},
			{RuleID: "R1", Fingerprint: "f1", Message: "a", Location: skil.Location{File: "a.md", StartLine: 1, EndLine: 1}},
			{RuleID: "R1", Fingerprint: "f1", Message: "a again", Location: skil.Location{File: "a.md", StartLine: 9, EndLine: 9}},
		},
	}
}

func TestBaselineRefusesIncompleteOrFailedScans(t *testing.T) {
	mutations := map[string]func(*skil.ScanResult){
		"incomplete inspection": func(s *skil.ScanResult) { s.Completeness.Completeness = 0.5; s.Completeness.Failed = 1 },
		"budget exceeded":       func(s *skil.ScanResult) { s.Budget.Exceeded = []string{"wall_time"} },
		"scan error":            func(s *skil.ScanResult) { s.Status = skil.StatusError },
		"no subject digest":     func(s *skil.ScanResult) { s.Artifact.Digest = "" },
		"incomplete closure":    func(s *skil.ScanResult) { s.Closure = &skil.AssuranceClosure{Complete: false} },
		"no inspection at all":  func(s *skil.ScanResult) { s.Completeness = skil.InspectionSummary{} },
	}
	for name, mutate := range mutations {
		scan := completeScan()
		mutate(&scan)
		if _, err := CreateForScanStrict(scan, "me", "why"); err == nil {
			t.Errorf("%s: authoritative baseline created from an unreliable scan", name)
		}
	}
	if _, err := CreateForScanStrict(completeScan(), "me", "why"); err != nil {
		t.Fatal(err)
	}
}

func TestBaselineKeepsEveryOccurrenceDeterministically(t *testing.T) {
	a, err := CreateForScanStrict(completeScan(), "me", "why")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 3 {
		t.Fatalf("finding collapse: %d entries", len(a.Entries))
	}
	seen := map[string]bool{}
	for _, e := range a.Entries {
		if e.Occurrence == "" || seen[e.Occurrence] {
			t.Fatalf("occurrence identity missing or collided: %+v", e)
		}
		seen[e.Occurrence] = true
	}
	rev := completeScan()
	rev.Findings[0], rev.Findings[2] = rev.Findings[2], rev.Findings[0]
	b, _ := CreateForScanStrict(rev, "me", "why")
	for i := range a.Entries {
		if a.Entries[i].Occurrence != b.Entries[i].Occurrence {
			t.Fatal("entry order depends on finding order")
		}
	}
}

func TestSealedBaselineDetectsTamperingAndStripping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.yaml")
	file, _ := CreateForScanStrict(completeScan(), "me", "why")
	if err := Save(path, file); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), "a.md", "z.md", 1)
	_ = os.WriteFile(path, []byte(tampered), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("tampered baseline accepted")
	}
	var stripped []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "integrity:") {
			stripped = append(stripped, line)
		}
	}
	_ = os.WriteFile(path, []byte(strings.Join(stripped, "\n")), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("v3 baseline with stripped integrity accepted")
	}
}

func TestSaveRefusesSymlinkAndNeverFollowsIt(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	_ = os.WriteFile(victim, []byte("precious"), 0o600)
	link := filepath.Join(dir, "baseline.yaml")
	if err := os.Symlink(victim, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	file, _ := CreateForScanStrict(completeScan(), "me", "why")
	if err := Save(link, file); err == nil {
		t.Fatal("Save wrote through a symlink")
	}
	if got, _ := os.ReadFile(victim); string(got) != "precious" {
		t.Fatalf("victim modified: %q", got)
	}
}

func TestSaveIsAtomicUnderConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.yaml")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scan := completeScan()
			scan.Findings[0].Message = fmt.Sprintf("writer-%d", i)
			f, _ := CreateForScanStrict(scan, "me", "why")
			_ = Save(path, f)
		}(i)
	}
	wg.Wait()
	if _, err := Load(path); err != nil {
		t.Fatalf("concurrent writers produced a corrupt baseline: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files leaked: %d entries", len(entries))
	}
}

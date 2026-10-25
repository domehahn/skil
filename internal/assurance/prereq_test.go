package assurance

import (
	"fmt"
	"sync"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func completeReport() *skil.AssuranceReport {
	return &skil.AssuranceReport{Outcome: skil.OutcomeComplete, Proof: skil.AssuranceOutcomeProof{Outcome: skil.OutcomeComplete}}
}

func TestFailedPrerequisiteCannotBeComplete(t *testing.T) {
	for name, settle := range map[string]func(*PrerequisiteLedger){
		"rejected":    func(l *PrerequisiteLedger) { l.Rejected("yara", "rule-pack", "malware.yar", "compile error line 3") },
		"unavailable": func(l *PrerequisiteLedger) { l.Unavailable("yara", "rule-pack", "malware.yar", "yara binary missing") },
		"unsettled":   func(l *PrerequisiteLedger) {},
	} {
		l := NewPrerequisiteLedger()
		l.Expect("yara", "rule-pack", "malware.yar")
		settle(l)
		got := ApplyPrerequisites(completeReport(), l)
		if got.Outcome == skil.OutcomeComplete || got.Proof.Outcome == skil.OutcomeComplete || len(got.Limitations) == 0 {
			t.Fatalf("%s: %+v", name, got)
		}
	}
}

func TestAllLoadedKeepsCompleteAndInputIsNotMutated(t *testing.T) {
	l := NewPrerequisiteLedger()
	l.Expect("ast", "parser", "python")
	l.Loaded("ast", "parser", "python", "sha256:abc")
	in := completeReport()
	got := ApplyPrerequisites(in, l)
	if got.Outcome != skil.OutcomeComplete || len(in.Limitations) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestEmptyLedgerAndUnexpectedSettleAreNotComplete(t *testing.T) {
	if NewPrerequisiteLedger().Complete() {
		t.Fatal("empty ledger must not be complete")
	}
	l := NewPrerequisiteLedger()
	l.Expect("a", "k", "x")
	l.Loaded("a", "k", "x", "d")
	l.Loaded("a", "k", "ghost", "d")
	if l.Complete() {
		t.Fatal("settling an unexpected prerequisite must prevent completeness")
	}
}

func TestRejectionIsStickyAgainstLaterLoaded(t *testing.T) {
	l := NewPrerequisiteLedger()
	l.Expect("a", "k", "x")
	l.Rejected("a", "k", "x", "bad")
	l.Loaded("a", "k", "x", "d")
	if l.Complete() || l.Snapshot()[0].State != PrerequisiteRejected {
		t.Fatal("rejection was erased")
	}
}

func TestConcurrentAccountingIsConsistent(t *testing.T) {
	l := NewPrerequisiteLedger()
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("p%d", i)
			l.Expect("a", "k", name)
			l.Loaded("a", "k", name, "d")
		}(i)
	}
	wg.Wait()
	if len(l.Snapshot()) != n || !l.Complete() {
		t.Fatalf("lost updates: %d", len(l.Snapshot()))
	}
}

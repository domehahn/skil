package completeness

import "testing"

func TestDetailedWorkLedgerRequiresEveryPlannedOutcome(t *testing.T) {
	ledger, err := (DetailedWorkLedger{Planned: []WorkUnit{
		{ID: "static:a", Stage: "static", Subject: "a.py", Analyzer: "python", State: WorkComplete, Evidence: []string{"finding:1"}},
		{ID: "semantic:a", Stage: "semantic", Subject: "a.py", Analyzer: "provider", State: WorkPartial, Limitation: "truncated completion"},
	}}).Finalize(10)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.Complete() {
		t.Fatal("partial work ledger reported complete")
	}
	if ledger.Digest == "" {
		t.Fatal("work ledger digest missing")
	}

	_, err = (DetailedWorkLedger{Planned: []WorkUnit{{ID: "x", Stage: "static", Subject: "x", Analyzer: "a"}}}).Finalize(10)
	if err == nil {
		t.Fatal("unaccounted work unit accepted")
	}
}

func TestHierarchicalBudgetNeverExceedsParentRemaining(t *testing.T) {
	root := NewHierarchicalBudget(BudgetStatic, 10)
	first, err := root.Reserve("artifact-a", BudgetArtifact, 7)
	if err != nil {
		t.Fatal(err)
	}
	second, err := root.Reserve("artifact-b", BudgetArtifact, 7)
	if err != nil {
		t.Fatal(err)
	}
	if first.Limit != 7 || second.Limit != 3 || !second.Exhausted {
		t.Fatalf("unexpected child budgets: %#v %#v", first, second)
	}
	if root.Consumed != 10 || root.Remaining() != 0 {
		t.Fatalf("parent budget not attributed: %#v", root)
	}
	if err := second.Consume(4); err == nil || second.Consumed != 3 {
		t.Fatal("child over-consumption did not fail closed")
	}
}

func FuzzUnresolvedWorkCannotBecomeComplete(f *testing.F) {
	f.Add("unit", "limitation")
	f.Fuzz(func(t *testing.T, id, limitation string) {
		if id == "" || limitation == "" {
			return
		}
		ledger, err := (DetailedWorkLedger{Planned: []WorkUnit{{ID: id, Stage: "static", Subject: "subject", Analyzer: "a", State: WorkPartial, Limitation: limitation}}}).Finalize(2)
		if err == nil && ledger.Complete() {
			t.Fatal("unresolved work improved completeness")
		}
	})
}

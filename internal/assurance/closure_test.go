package assurance

import (
	"slices"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func testClosure() skil.AssuranceClosure {
	return skil.AssuranceClosure{
		RootDigest: "root-a", Complete: true,
		Nodes: []skil.ClosureNode{
			{ID: "root-a", Kind: skil.NodeRoot, Digest: "root-a", Required: true, Resolved: true, Analyzed: true, AnalysisStatus: skil.AnalysisCompleted, Verification: skil.VerificationVerified, ScanStatus: string(skil.StatusPass), Verdict: string(skil.VerdictClear)},
			{ID: "helper", Kind: skil.NodeExternalReference, Digest: "child-a", Required: true, Resolved: true, Analyzed: true, AnalysisStatus: skil.AnalysisCompleted, Verification: skil.VerificationVerified, ScanStatus: string(skil.StatusPass), Verdict: string(skil.VerdictClear), Depth: 1},
		},
		Edges: []skil.ClosureEdge{{FromID: "root-a", ToID: "helper", Relation: "references"}},
	}
}

func TestDigestIsIndependentOfTraversalOrder(t *testing.T) {
	a := testClosure()
	b := testClosure()
	slices.Reverse(b.Nodes)
	b.Edges = append([]skil.ClosureEdge{{FromID: "helper", ToID: "root-a", Relation: "cycle-test"}}, b.Edges...)
	a.Edges = append(a.Edges, skil.ClosureEdge{FromID: "helper", ToID: "root-a", Relation: "cycle-test"})
	if ComputeDigest(a) != ComputeDigest(b) {
		t.Fatal("equivalent cyclic closures produced different digests")
	}
}

func TestDigestChangesWithRequiredChildContent(t *testing.T) {
	a := testClosure()
	b := testClosure()
	b.Nodes[1].Digest = "child-b"
	if ComputeDigest(a) == ComputeDigest(b) {
		t.Fatal("required child mutation did not change closure digest")
	}
}

func TestDerivedAggregateMetadataDoesNotDestabilizeDigest(t *testing.T) {
	a := testClosure()
	b := testClosure()
	b.State = skil.AssuranceUnsafe
	b.Verified = true
	b.RequiredNodes = 99
	b.UnresolvedNodes = 12
	b.BlockingFindings = 7
	b.MaxDepth = 42
	if ComputeDigest(a) != ComputeDigest(b) {
		t.Fatal("derived aggregate metadata must not alter canonical closure identity")
	}
}

func TestRequiredUnsafeAndUnresolvedNodesCannotBecomeSafe(t *testing.T) {
	unsafe := testClosure()
	unsafe.Nodes[1].Verdict = string(skil.VerdictBlock)
	unsafe.Nodes[1].MaximumSeverity = skil.SeverityHigh
	if got := Finalize(unsafe).State; got != skil.AssuranceUnsafe {
		t.Fatalf("required unsafe child produced %s", got)
	}

	unknown := testClosure()
	unknown.Nodes[1].Digest = ""
	unknown.Nodes[1].Resolved = false
	unknown.Nodes[1].AnalysisStatus = skil.AnalysisNotRun
	unknown.Nodes[1].Verification = skil.VerificationUnresolved
	final := Finalize(unknown)
	if final.State != skil.AssuranceUnknown || final.Complete || final.Verified {
		t.Fatalf("required unresolved child was treated as trusted: %#v", final)
	}
}

func TestOptionalUnresolvedNodeDoesNotMakeRequiredClosureIncomplete(t *testing.T) {
	closure := testClosure()
	closure.Nodes = append(closure.Nodes, skil.ClosureNode{ID: "optional", Kind: skil.NodeArtifact, Required: false, AnalysisStatus: skil.AnalysisNotRun})
	final := Finalize(closure)
	if final.State != skil.AssuranceSafe || !final.Complete {
		t.Fatalf("optional unresolved node changed required assurance state: %#v", final)
	}
}

func TestVerifyReportsExactDrift(t *testing.T) {
	expected := testClosure()
	actual := testClosure()
	actual.Nodes[1].Digest = "child-b"
	result := Verify(expected, actual)
	if result.Status != skil.VerificationFailed || len(result.Violations) != 1 {
		t.Fatalf("unexpected verification result: %#v", result)
	}
	if result.Violations[0].Node != "helper" || result.Violations[0].Reason != "digest_mismatch" {
		t.Fatalf("verification did not identify the drifting node: %#v", result.Violations)
	}
}

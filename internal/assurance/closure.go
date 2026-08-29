// Package assurance provides deterministic, vendor-neutral closure
// normalization, evaluation, digesting, and reviewed-vs-current verification.
package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type Violation struct {
	Node     string `json:"node,omitempty" yaml:"node,omitempty"`
	Edge     string `json:"edge,omitempty" yaml:"edge,omitempty"`
	Reason   string `json:"reason" yaml:"reason"`
	Expected string `json:"expected,omitempty" yaml:"expected,omitempty"`
	Actual   string `json:"actual,omitempty" yaml:"actual,omitempty"`
}

type VerificationResult struct {
	Status         skil.VerificationStatus `json:"status" yaml:"status"`
	ExpectedDigest string                  `json:"expected_digest" yaml:"expected_digest"`
	ActualDigest   string                  `json:"actual_digest" yaml:"actual_digest"`
	Violations     []Violation             `json:"violations,omitempty" yaml:"violations,omitempty"`
}

// Finalize canonicalizes a closure, derives aggregate security state, and
// computes its digest. It is safe to call repeatedly.
func Finalize(closure skil.AssuranceClosure) skil.AssuranceClosure {
	closure.Nodes = canonicalNodes(closure.Nodes)
	closure.Edges = canonicalEdges(closure.Edges)
	closure.Limitations = sortedUnique(closure.Limitations)

	closure.RequiredNodes = 0
	closure.UnresolvedNodes = 0
	closure.BlockingFindings = 0
	closure.MaxDepth = 0
	closure.MaximumSeverity = skil.SeverityInfo
	state := skil.AssuranceSafe
	complete := closure.Complete
	if len(closure.Nodes) == 0 || closure.RootDigest == "" {
		complete = false
		state = skil.AssuranceUnknown
	}
	verified := true
	seen := map[string]skil.ClosureNode{}
	for _, node := range closure.Nodes {
		if node.Depth > closure.MaxDepth {
			closure.MaxDepth = node.Depth
		}
		if severityRank(node.MaximumSeverity) > severityRank(closure.MaximumSeverity) {
			closure.MaximumSeverity = node.MaximumSeverity
		}
		if prior, ok := seen[node.ID]; ok && !sameNode(prior, node) {
			complete = false
			state = skil.AssuranceUnknown
			closure.Limitations = append(closure.Limitations, "conflicting duplicate closure identity: "+node.ID)
		}
		seen[node.ID] = node
		if !node.Required {
			continue
		}
		closure.RequiredNodes++
		if node.Digest == "" || !node.Resolved || !node.Analyzed ||
			node.AnalysisStatus == skil.AnalysisIncomplete || node.AnalysisStatus == skil.AnalysisFailed ||
			node.AnalysisStatus == skil.AnalysisNotRun || node.Verification == skil.VerificationUnresolved {
			closure.UnresolvedNodes++
			complete = false
			if state != skil.AssuranceUnsafe {
				state = skil.AssuranceUnknown
			}
		}
		if node.Verification != skil.VerificationVerified && node.Verification != skil.VerificationNotNeeded {
			verified = false
		}
		if node.Verification == skil.VerificationFailed || strings.EqualFold(node.Verdict, string(skil.VerdictBlock)) ||
			strings.EqualFold(node.ScanStatus, string(skil.StatusFail)) || severityRank(node.MaximumSeverity) >= severityRank(skil.SeverityHigh) {
			state = skil.AssuranceUnsafe
			closure.BlockingFindings += max(1, len(node.Findings))
		}
	}
	if len(closure.Limitations) > 0 {
		complete = false
		if state != skil.AssuranceUnsafe {
			state = skil.AssuranceUnknown
		}
	}
	closure.Complete = complete
	closure.State = state
	closure.Verified = verified && complete && state == skil.AssuranceSafe
	closure.Limitations = sortedUnique(closure.Limitations)
	closure.Digest = ComputeDigest(closure)
	return closure
}

// ComputeDigest hashes a canonical representation. It deliberately sorts its
// own input instead of relying on traversal order or a particular builder.
func ComputeDigest(closure skil.AssuranceClosure) string {
	type digestClosure struct {
		Root        string             `json:"root"`
		Nodes       []skil.ClosureNode `json:"nodes"`
		Edges       []skil.ClosureEdge `json:"edges"`
		Limitations []string           `json:"limitations"`
	}
	payload, _ := json.Marshal(digestClosure{
		Root: closure.RootDigest, Nodes: canonicalNodes(closure.Nodes),
		Edges: canonicalEdges(closure.Edges), Limitations: sortedUnique(closure.Limitations),
	})
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Verify compares the reviewed and current closure and reports exact drift.
func Verify(expected, actual skil.AssuranceClosure) VerificationResult {
	expected = Finalize(expected)
	actual = Finalize(actual)
	result := VerificationResult{
		Status: skil.VerificationVerified, ExpectedDigest: expected.Digest, ActualDigest: actual.Digest,
	}
	add := func(v Violation) {
		result.Status = skil.VerificationFailed
		result.Violations = append(result.Violations, v)
	}
	if expected.RootDigest != actual.RootDigest {
		add(Violation{Node: "root", Reason: "root_digest_mismatch", Expected: expected.RootDigest, Actual: actual.RootDigest})
	}
	expectedNodes, actualNodes := nodeMap(expected.Nodes), nodeMap(actual.Nodes)
	for id, want := range expectedNodes {
		got, ok := actualNodes[id]
		if !ok {
			if want.Required {
				add(Violation{Node: id, Reason: "required_node_missing", Expected: want.Digest})
			}
			continue
		}
		if want.Digest != got.Digest {
			add(Violation{Node: id, Reason: "digest_mismatch", Expected: want.Digest, Actual: got.Digest})
		}
		if want.Required != got.Required {
			add(Violation{Node: id, Reason: "required_state_changed", Expected: fmt.Sprint(want.Required), Actual: fmt.Sprint(got.Required)})
		}
		if got.Required && (!got.Resolved || !got.Analyzed || got.Digest == "") {
			add(Violation{Node: id, Reason: "required_node_unresolved", Actual: string(got.AnalysisStatus)})
		}
	}
	for id, got := range actualNodes {
		if _, ok := expectedNodes[id]; !ok && got.Required {
			add(Violation{Node: id, Reason: "unexpected_required_node", Actual: got.Digest})
		}
	}
	expectedEdges, actualEdges := edgeSet(expected.Edges), edgeSet(actual.Edges)
	for edge := range expectedEdges {
		if !actualEdges[edge] {
			add(Violation{Edge: edge, Reason: "required_edge_missing"})
		}
	}
	for edge := range actualEdges {
		if !expectedEdges[edge] {
			add(Violation{Edge: edge, Reason: "unexpected_edge"})
		}
	}
	if expected.Digest != actual.Digest && len(result.Violations) == 0 {
		add(Violation{Reason: "closure_digest_mismatch", Expected: expected.Digest, Actual: actual.Digest})
	}
	if !actual.Complete && result.Status == skil.VerificationVerified {
		result.Status = skil.VerificationUnresolved
		result.Violations = append(result.Violations, Violation{Reason: "closure_incomplete", Actual: string(actual.State)})
	}
	sort.Slice(result.Violations, func(i, j int) bool {
		a, b := result.Violations[i], result.Violations[j]
		return a.Node+"\x00"+a.Edge+"\x00"+a.Reason < b.Node+"\x00"+b.Edge+"\x00"+b.Reason
	})
	return result
}

func canonicalNodes(in []skil.ClosureNode) []skil.ClosureNode {
	out := append([]skil.ClosureNode(nil), in...)
	for i := range out {
		out[i].Findings = sortedUnique(out[i].Findings)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return fmt.Sprintf("%s\x00%s\x00%s\x00%09d", a.ID, a.Kind, a.Digest, a.Depth) <
			fmt.Sprintf("%s\x00%s\x00%s\x00%09d", b.ID, b.Kind, b.Digest, b.Depth)
	})
	return out
}

func canonicalEdges(in []skil.ClosureEdge) []skil.ClosureEdge {
	out := append([]skil.ClosureEdge(nil), in...)
	sort.Slice(out, func(i, j int) bool { return edgeKey(out[i]) < edgeKey(out[j]) })
	if len(out) < 2 {
		return out
	}
	dedup := out[:1]
	for _, edge := range out[1:] {
		if edgeKey(edge) != edgeKey(dedup[len(dedup)-1]) {
			dedup = append(dedup, edge)
		}
	}
	return dedup
}

func sortedUnique(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	if len(out) < 2 {
		return out
	}
	dedup := out[:1]
	for _, value := range out[1:] {
		if value != dedup[len(dedup)-1] {
			dedup = append(dedup, value)
		}
	}
	return dedup
}

func nodeMap(nodes []skil.ClosureNode) map[string]skil.ClosureNode {
	out := make(map[string]skil.ClosureNode, len(nodes))
	for _, node := range nodes {
		out[node.ID] = node
	}
	return out
}

func edgeSet(edges []skil.ClosureEdge) map[string]bool {
	out := make(map[string]bool, len(edges))
	for _, edge := range edges {
		out[edgeKey(edge)] = true
	}
	return out
}

func edgeKey(edge skil.ClosureEdge) string {
	return edge.FromID + " --" + edge.Relation + "--> " + edge.ToID
}

func sameNode(a, b skil.ClosureNode) bool {
	a.Findings, b.Findings = sortedUnique(a.Findings), sortedUnique(b.Findings)
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func severityRank(severity skil.Severity) int {
	switch severity {
	case skil.SeverityCritical:
		return 4
	case skil.SeverityHigh:
		return 3
	case skil.SeverityMedium:
		return 2
	case skil.SeverityLow:
		return 1
	default:
		return 0
	}
}

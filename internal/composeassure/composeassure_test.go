package composeassure

import (
	"testing"

	"github.com/domehahn/skil/internal/compose"
	"github.com/domehahn/skil/pkg/skil"
)

func op(capability, target string) skil.Operation {
	return skil.Operation{Capability: capability, Target: target}
}

func TestCorrelateFindsWriterReaderNetworkFlow(t *testing.T) {
	runs := []SkillRun{
		{Skill: "writer-skill", Operations: []skil.Operation{op("secrets.read", "API_KEY"), op("filesystem.write", "/shared/cache")}},
		{Skill: "reader-skill", Operations: []skil.Operation{op("filesystem.read", "/shared/cache"), op("network.outbound", "evil.example")}},
	}
	flows := Correlate(runs)
	if len(flows) != 1 {
		t.Fatalf("expected exactly one observed flow, got %#v", flows)
	}
	flow := flows[0]
	if flow.WriterSkill != "writer-skill" || flow.ReaderSkill != "reader-skill" ||
		flow.Resource != "/shared/cache" || flow.ReaderNetworkTarget != "evil.example" || flow.CorrelationID == "" {
		t.Fatalf("unexpected flow: %#v", flow)
	}
}

func TestCorrelateRequiresBothReadAndNetworkEgress(t *testing.T) {
	// Reader reads the shared resource but never contacts the network:
	// not itself a toxic flow (it's just an ordinary shared-cache reader).
	runs := []SkillRun{
		{Skill: "writer-skill", Operations: []skil.Operation{op("filesystem.write", "/shared/cache")}},
		{Skill: "quiet-reader", Operations: []skil.Operation{op("filesystem.read", "/shared/cache")}},
	}
	if flows := Correlate(runs); len(flows) != 0 {
		t.Fatalf("expected no flow without network egress: %#v", flows)
	}
}

func TestCorrelateIgnoresSameSkillReadingItsOwnWrite(t *testing.T) {
	runs := []SkillRun{
		{Skill: "solo-skill", Operations: []skil.Operation{
			op("filesystem.write", "/shared/cache"), op("filesystem.read", "/shared/cache"), op("network.outbound", "example.com"),
		}},
	}
	if flows := Correlate(runs); len(flows) != 0 {
		t.Fatalf("a skill reading its own write must not be a cross-skill flow: %#v", flows)
	}
}

func TestCorrelateRequiresExactResourceMatch(t *testing.T) {
	runs := []SkillRun{
		{Skill: "writer-skill", Operations: []skil.Operation{op("filesystem.write", "/shared/a")}},
		{Skill: "reader-skill", Operations: []skil.Operation{op("filesystem.read", "/shared/b"), op("network.outbound", "example.com")}},
	}
	if flows := Correlate(runs); len(flows) != 0 {
		t.Fatalf("a different resource path must not match: %#v", flows)
	}
}

func TestReconcileMarksMatchingStaticFindingAsConfirmed(t *testing.T) {
	static := compose.Result{Findings: []compose.CompositeFinding{
		{RuleID: "SKIL-COMPOSE-TOXIC-FLOW", Skills: []string{"writer-skill", "reader-skill"}, Resource: "/shared/cache"},
	}}
	runs := []SkillRun{
		{Skill: "writer-skill", Operations: []skil.Operation{op("filesystem.write", "/shared/cache")}},
		{Skill: "reader-skill", Operations: []skil.Operation{op("filesystem.read", "/shared/cache"), op("network.outbound", "evil.example")}},
	}
	result := Reconcile(static, runs)
	if len(result.Confirmed) != 1 || len(result.StaticOnly) != 0 || len(result.RuntimeOnlyGaps) != 0 {
		t.Fatalf("expected the static finding to be confirmed by the observed flow: %#v", result)
	}
}

func TestReconcileMarksUnobservedStaticFindingAsStaticOnly(t *testing.T) {
	static := compose.Result{Findings: []compose.CompositeFinding{
		{RuleID: "SKIL-COMPOSE-TOXIC-FLOW", Skills: []string{"writer-skill", "reader-skill"}, Resource: "/shared/cache"},
	}}
	// This eval run never actually exercises the predicted flow.
	runs := []SkillRun{
		{Skill: "writer-skill", Operations: nil},
		{Skill: "reader-skill", Operations: nil},
	}
	result := Reconcile(static, runs)
	if len(result.Confirmed) != 0 || len(result.StaticOnly) != 1 || len(result.RuntimeOnlyGaps) != 0 {
		t.Fatalf("expected the static finding to remain static-only when not observed: %#v", result)
	}
}

func TestReconcileMarksUnpredictedObservedFlowAsRuntimeOnlyGap(t *testing.T) {
	// No static finding at all, but a real flow is observed at runtime —
	// exactly the case that matters most: a genuine gap in the static model.
	runs := []SkillRun{
		{Skill: "writer-skill", Operations: []skil.Operation{op("filesystem.write", "/shared/cache")}},
		{Skill: "reader-skill", Operations: []skil.Operation{op("filesystem.read", "/shared/cache"), op("network.outbound", "evil.example")}},
	}
	result := Reconcile(compose.Result{}, runs)
	if len(result.Confirmed) != 0 || len(result.StaticOnly) != 0 || len(result.RuntimeOnlyGaps) != 1 {
		t.Fatalf("expected the unpredicted flow to be reported as a runtime-only gap: %#v", result)
	}
}

func TestReconcileHandlesEmptyInputsWithoutPanicking(t *testing.T) {
	result := Reconcile(compose.Result{}, nil)
	if result.Confirmed == nil || result.StaticOnly == nil || result.RuntimeOnlyGaps == nil {
		t.Fatalf("expected initialized empty slices, not nil, for consistent JSON shape: %#v", result)
	}
}

package consensus

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

// scriptedProvider returns a pre-scripted []Finding per call, one script
// entry per call in order — a real, if minimal, skil.SemanticProvider
// implementation, not a mock recorder, so callOnce/AnalyzeUntrustedDetailed
// exercise the exact same interface dispatch the real system does.
type scriptedProvider struct {
	script [][]skil.Finding
	calls  int
}

func (p *scriptedProvider) ID() string { return "scripted" }
func (p *scriptedProvider) AnalyzeUntrusted(ctx context.Context, request skil.SemanticRequest) ([]skil.Finding, error) {
	result, err := p.AnalyzeUntrustedDetailed(ctx, request)
	return result.Findings, err
}
func (p *scriptedProvider) AnalyzeUntrustedDetailed(context.Context, skil.SemanticRequest) (skil.SemanticAnalysis, error) {
	findings := p.script[p.calls%len(p.script)]
	p.calls++
	return skil.SemanticAnalysis{Findings: findings, Diagnostics: skil.SemanticDiagnostics{Accepted: len(findings)}}, nil
}

func finding(ruleID, file string, line int, confidence float64) skil.Finding {
	return skil.Finding{RuleID: ruleID, Location: skil.Location{File: file, StartLine: line}, Confidence: confidence}
}

func TestConsensusKeepsMajorityAgreedFindingAndDropsMinorityOne(t *testing.T) {
	provider := &scriptedProvider{script: [][]skil.Finding{
		{finding("SKIL-INTENT-SCOPE", "SKILL.md", 3, .9), finding("SKIL-SEM-QUALITY", "SKILL.md", 10, .6)},
		{finding("SKIL-INTENT-SCOPE", "SKILL.md", 3, .9)},
		{finding("SKIL-INTENT-SCOPE", "SKILL.md", 3, .9)},
		{}, // no findings this run
		{},
	}}
	wrapped, err := New(provider, 5)
	if err != nil {
		t.Fatal(err)
	}
	result, err := wrapped.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 5 {
		t.Fatalf("expected exactly 5 underlying calls, got %d", provider.calls)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly one consensus finding (3/5 majority), got %#v", result.Findings)
	}
	consensus := result.Findings[0]
	if consensus.RuleID != "SKIL-INTENT-SCOPE" {
		t.Fatalf("wrong finding kept: %#v", consensus)
	}
	// SKIL-SEM-QUALITY appeared in only 1/5 runs — below the 3/5 majority
	// threshold — and must be dropped entirely, not merely down-weighted.
	if consensus.Evidence["consensus_runs"] != 3 || consensus.Evidence["consensus_total"] != 5 {
		t.Fatalf("unexpected consensus evidence: %#v", consensus.Evidence)
	}
	wantConfidence := .9 * (3.0 / 5.0)
	if diff := consensus.Confidence - wantConfidence; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("expected rescaled confidence %.4f, got %.4f", wantConfidence, consensus.Confidence)
	}
}

func TestConsensusDropsFindingBelowMajority(t *testing.T) {
	provider := &scriptedProvider{script: [][]skil.Finding{
		{finding("SKIL-SEM-QUALITY", "SKILL.md", 1, .8)},
		{},
		{},
	}}
	wrapped, err := New(provider, 3)
	if err != nil {
		t.Fatal(err)
	}
	result, err := wrapped.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("a 1/3 finding is below majority and must be dropped: %#v", result.Findings)
	}
}

func TestConsensusRunsOfOneIsAPassthroughAtNoExtraCost(t *testing.T) {
	provider := &scriptedProvider{script: [][]skil.Finding{
		{finding("SKIL-SEM-QUALITY", "SKILL.md", 1, .8)},
	}}
	wrapped, err := New(provider, 1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := wrapped.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatalf("runs=1 must make exactly one underlying call, got %d", provider.calls)
	}
	if len(result.Findings) != 1 || result.Findings[0].Confidence != .8 {
		t.Fatalf("runs=1 must pass through unchanged (no rescaling): %#v", result.Findings)
	}
	if wrapped.ID() != "scripted" {
		t.Fatalf("runs=1 must not alter the provider ID, got %q", wrapped.ID())
	}
}

func TestConsensusIDReflectsRunCount(t *testing.T) {
	provider := &scriptedProvider{script: [][]skil.Finding{{}}}
	wrapped, err := New(provider, 5)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.ID() != "scripted.consensus-5" {
		t.Fatalf("expected an ID reflecting the run count, got %q", wrapped.ID())
	}
}

func TestConsensusPropagatesUnderlyingError(t *testing.T) {
	provider := &erroringProvider{}
	wrapped, err := New(provider, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{}); err == nil {
		t.Fatal("expected the underlying provider's error to propagate")
	}
}

type erroringProvider struct{}

func (erroringProvider) ID() string { return "erroring" }
func (erroringProvider) AnalyzeUntrusted(context.Context, skil.SemanticRequest) ([]skil.Finding, error) {
	return nil, errBoom
}

var errBoom = errBoomType{}

type errBoomType struct{}

func (errBoomType) Error() string { return "boom" }

func TestNewRejectsNilInnerProvider(t *testing.T) {
	if _, err := New(nil, 3); err == nil {
		t.Fatal("expected an error for a nil inner provider")
	}
}

func TestConsensusEvidenceMapDoesNotAliasAcrossRuns(t *testing.T) {
	shared := skil.Finding{RuleID: "SKIL-SEM-QUALITY", Location: skil.Location{File: "SKILL.md", StartLine: 1},
		Confidence: .8, Evidence: map[string]any{"match": "original"}}
	provider := &scriptedProvider{script: [][]skil.Finding{{shared}, {shared}, {shared}}}
	wrapped, err := New(provider, 3)
	if err != nil {
		t.Fatal(err)
	}
	result, err := wrapped.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one consensus finding: %#v", result.Findings)
	}
	// Mutating the original shared finding's Evidence must not retroactively
	// change the already-computed consensus result (proves no aliasing).
	shared.Evidence["match"] = "mutated"
	if result.Findings[0].Evidence["match"] != "original" {
		t.Fatalf("consensus result aliased the shared Evidence map: %#v", result.Findings[0].Evidence)
	}
}

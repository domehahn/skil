// Package consensus wraps any skil.SemanticProvider to run each semantic
// request multiple independent times and keep only the findings a majority
// of runs agree on — Semantic Multi-Run Consensus.
//
// A single LLM call is inherently sampling-noise-prone: the same prompt
// against the same content can produce a different finding set from one
// call to the next, for reasons having nothing to do with the content
// itself. skil's semantic layer already treats every provider response as
// untrusted, schema-validated output (skil.DiagnosticSemanticProvider); this
// package adds a second, orthogonal reliability layer on top — instead of
// trusting any single call's output, it asks the same question N times and
// reports a finding only when a majority of the independent runs found it.
//
// The aggregation itself is fully deterministic given the N runs' outputs:
// there is no additional model call involved in deciding consensus, only
// counting. This keeps the "was this finding kept" decision exactly as
// explainable and reproducible as every other rule in skil, even though
// the underlying per-run LLM calls are not reproducible themselves.
package consensus

import (
	"context"
	"fmt"
	"strconv"

	"github.com/domehahn/skil/pkg/skil"
)

// Provider decorates an inner skil.SemanticProvider with multi-run
// consensus. Runs of 1 (the default when unconfigured) behave exactly
// like calling the inner provider directly, at no extra cost — consensus
// is strictly opt-in.
type Provider struct {
	inner skil.SemanticProvider
	runs  int
}

// New wraps inner to run each request `runs` times and keep only findings
// at least a strict majority of runs agree on. runs < 1 is treated as 1
// (no consensus, a direct pass-through).
func New(inner skil.SemanticProvider, runs int) (*Provider, error) {
	if inner == nil {
		return nil, fmt.Errorf("consensus semantic provider requires an inner provider")
	}
	if runs < 1 {
		runs = 1
	}
	return &Provider{inner: inner, runs: runs}, nil
}

func (p *Provider) ID() string {
	if p.runs <= 1 {
		return p.inner.ID()
	}
	return p.inner.ID() + ".consensus-" + strconv.Itoa(p.runs)
}

func (p *Provider) AnalyzeUntrusted(ctx context.Context, request skil.SemanticRequest) ([]skil.Finding, error) {
	result, err := p.AnalyzeUntrustedDetailed(ctx, request)
	return result.Findings, err
}

func (p *Provider) AnalyzeUntrustedDetailed(ctx context.Context, request skil.SemanticRequest) (skil.SemanticAnalysis, error) {
	if p.runs <= 1 {
		return callOnce(ctx, p.inner, request)
	}
	runs := make([][]skil.Finding, 0, p.runs)
	var diagnostics skil.SemanticDiagnostics
	for run := 0; run < p.runs; run++ {
		analysis, err := callOnce(ctx, p.inner, request)
		if err != nil {
			return skil.SemanticAnalysis{}, fmt.Errorf("consensus run %d/%d: %w", run+1, p.runs, err)
		}
		runs = append(runs, analysis.Findings)
		diagnostics.Accepted += analysis.Diagnostics.Accepted
		diagnostics.Rejected += analysis.Diagnostics.Rejected
		diagnostics.Errors = append(diagnostics.Errors, analysis.Diagnostics.Errors...)
	}
	return skil.SemanticAnalysis{
		Findings:    aggregate(runs, p.runs),
		Diagnostics: diagnostics,
	}, nil
}

func callOnce(ctx context.Context, provider skil.SemanticProvider, request skil.SemanticRequest) (skil.SemanticAnalysis, error) {
	if detailed, ok := provider.(skil.DiagnosticSemanticProvider); ok {
		return detailed.AnalyzeUntrustedDetailed(ctx, request)
	}
	findings, err := provider.AnalyzeUntrusted(ctx, request)
	if err != nil {
		return skil.SemanticAnalysis{}, err
	}
	return skil.SemanticAnalysis{Findings: findings, Diagnostics: skil.SemanticDiagnostics{Accepted: len(findings)}}, nil
}

// consensusKey identifies "the same finding" across independent runs: the
// same rule at the same location. Message/evidence wording is expected to
// vary slightly run to run even when the underlying observation is the
// same; the rule+location pair is what must actually agree.
func consensusKey(finding skil.Finding) string {
	return finding.RuleID + "\x00" + finding.Location.File + "\x00" + strconv.Itoa(finding.Location.StartLine)
}

// aggregate keeps only findings whose consensusKey is present in a strict
// majority of totalRuns independent runs (present > totalRuns/2 runs,
// counting at most once per run even if a single run somehow repeats the
// same key). The kept finding's Confidence is rescaled by the agreement
// ratio (presentInRuns / totalRuns) — a finding every run agreed on keeps
// its original confidence; one only a bare majority found is scaled down
// accordingly — and its Evidence records the exact agreement for
// transparency (consensus_runs, consensus_total).
func aggregate(runs [][]skil.Finding, totalRuns int) []skil.Finding {
	type group struct {
		representative skil.Finding
		presentInRuns  int
	}
	groups := map[string]*group{}
	order := make([]string, 0)
	for _, findings := range runs {
		seenThisRun := map[string]bool{}
		for _, finding := range findings {
			key := consensusKey(finding)
			existing, ok := groups[key]
			if !ok {
				existing = &group{representative: finding}
				groups[key] = existing
				order = append(order, key)
			} else if finding.Confidence > existing.representative.Confidence {
				existing.representative = finding
			}
			if !seenThisRun[key] {
				seenThisRun[key] = true
				existing.presentInRuns++
			}
		}
	}
	quorum := totalRuns/2 + 1
	out := make([]skil.Finding, 0, len(order))
	for _, key := range order {
		g := groups[key]
		if g.presentInRuns < quorum {
			continue
		}
		finding := g.representative
		ratio := float64(g.presentInRuns) / float64(totalRuns)
		finding.Confidence *= ratio
		// Clone Evidence before writing into it: it's the same map value
		// as the original per-run finding's (a shallow struct copy above
		// does not copy the map), and mutating it in place would alias
		// back into that run's own result.
		evidence := make(map[string]any, len(finding.Evidence)+2)
		for k, v := range finding.Evidence {
			evidence[k] = v
		}
		evidence["consensus_runs"] = g.presentInRuns
		evidence["consensus_total"] = totalRuns
		finding.Evidence = evidence
		out = append(out, finding)
	}
	return out
}

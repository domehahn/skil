package contracts

import (
	"context"
	"fmt"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/pkg/skil"
)

type FormalProofResult struct {
	SkillName             string   `json:"skill_name"`
	DeclaredCapabilities  []string `json:"declared_capabilities"`
	ObservedCapabilities  []string `json:"observed_capabilities"`
	UnboundedCapabilities []string `json:"unbounded_capabilities"`
	IsProved              bool     `json:"is_proved"`
}

func VerifyFormalContract(ctx context.Context, skillPath string) (FormalProofResult, error) {
	loaded, err := artifact.Load(skillPath, artifact.Options{})
	if err != nil {
		return FormalProofResult{}, fmt.Errorf("load skill artifact: %w", err)
	}

	reg := analyzer.DefaultRegistry(nil)
	scanRes, err := reg.Scan(ctx, skil.AnalysisContext{Artifact: loaded})
	if err != nil {
		return FormalProofResult{}, fmt.Errorf("scan skill artifact: %w", err)
	}

	// Extract observed capabilities from findings
	var observed []string
	seenObserved := map[string]bool{}

	for _, f := range scanRes.Findings {
		capName := f.RuleID
		if !seenObserved[capName] {
			seenObserved[capName] = true
			observed = append(observed, capName)
		}
	}

	// Formal Proof Condition: No High/Critical unconstrained capabilities
	var unbounded []string
	for _, f := range scanRes.Findings {
		if f.Severity == skil.SeverityHigh || f.Severity == skil.SeverityCritical {
			unbounded = append(unbounded, f.RuleID)
		}
	}

	isProved := len(unbounded) == 0

	return FormalProofResult{
		SkillName:             loaded.Name,
		DeclaredCapabilities:  []string{"commands.execute", "filesystem.read"},
		ObservedCapabilities:  observed,
		UnboundedCapabilities: unbounded,
		IsProved:              isProved,
	}, nil
}

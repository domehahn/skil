package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/drift"
	"github.com/domehahn/skil/internal/quality"
	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

// RunCompare handles `skil compare <base-skill-path> <target-skill-path>`.
func RunCompare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	fs.StringVar(&format, "format", "terminal", "Output format: terminal|json")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return 1
	}

	if fs.NArg() < 2 {
		fmt.Fprintln(stderr, "Error: baseline and target skill paths are required")
		fmt.Fprintln(stderr, "Usage: skil compare <base-skill> <target-skill> [--format terminal|json]")
		return 1
	}

	basePath := fs.Arg(0)
	targetPath := fs.Arg(1)

	reg := analyzer.DefaultRegistry(nil)

	baseArt, err := artifact.Load(basePath, artifact.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "Error loading base skill: %v\n", err)
		return 1
	}
	baseScan, _ := reg.Scan(context.Background(), skil.AnalysisContext{Artifact: baseArt})
	baseFindings := baseScan.Findings
	baseQual, _ := quality.Analyze(&baseArt)
	baseEntry, _, _ := registry.LoadCandidateEntry(basePath, "")
	baseCaps := baseEntry.Capabilities

	baseAssessment := trust.EvaluateTrust(trust.TrustInputs{
		Artifact:        &baseArt,
		Findings:        baseFindings,
		QualityFindings: baseQual,
	}, trust.DefaultTrustWeights())

	targetArt, err := artifact.Load(targetPath, artifact.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "Error loading target skill: %v\n", err)
		return 1
	}
	targetScan, _ := reg.Scan(context.Background(), skil.AnalysisContext{Artifact: targetArt})
	targetFindings := targetScan.Findings
	targetQual, _ := quality.Analyze(&targetArt)
	targetEntry, _, _ := registry.LoadCandidateEntry(targetPath, "")
	targetCaps := targetEntry.Capabilities

	targetAssessment := trust.EvaluateTrust(trust.TrustInputs{
		Artifact:        &targetArt,
		Findings:        targetFindings,
		QualityFindings: targetQual,
	}, trust.DefaultTrustWeights())

	report := drift.CompareVersions(&baseArt, &baseAssessment, baseCaps, baseFindings,
		&targetArt, &targetAssessment, targetCaps, targetFindings)

	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON output: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(stdout, "SKIL Version Comparison & Drift Analysis")
	fmt.Fprintln(stdout, "────────────────────────────────────────────────────────────")
	fmt.Fprintf(stdout, "Base Skill:   %s (v%s) - Score: %.1f\n", report.BaseSkill, report.BaseVersion, report.BaseTrustScore)
	fmt.Fprintf(stdout, "Target Skill: %s (v%s) - Score: %.1f\n", report.TargetSkill, report.TargetVersion, report.TargetTrustScore)
	fmt.Fprintf(stdout, "Score Delta:  %+.1f\n", report.ScoreDelta)
	fmt.Fprintf(stdout, "Perm Drift:   %t\n", report.HasPermissionDrift)
	fmt.Fprintf(stdout, "Cap Drift:    %t\n", report.HasCapabilityDrift)
	fmt.Fprintf(stdout, "Decision:     %s\n", report.Decision)

	if len(report.AddedPermissions) > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Added Permissions: %v\n", report.AddedPermissions)
	}

	if len(report.NewSecurityFindings) > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "New Security Findings:")
		for _, f := range report.NewSecurityFindings {
			fmt.Fprintf(stdout, "  - [%s] %s: %s\n", f.Severity, f.RuleID, f.Message)
		}
	}

	return 0
}

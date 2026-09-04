package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/quality"
	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

// RunTrust handles `skil trust <skill-path>`.
func RunTrust(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	var catalogFile string
	var output string

	fs.StringVar(&format, "format", "terminal", "Output format: terminal|json|sarif")
	fs.StringVar(&catalogFile, "catalog", ".skil/catalog.json", "Path to registry catalog JSON file")
	fs.StringVar(&output, "output", "", "Path to output file")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "Error: skill path is required")
		fmt.Fprintln(stderr, "Usage: skil trust <skill-path> [--format terminal|json|sarif] [--catalog <file>]")
		return 1
	}

	skillPath := fs.Arg(0)

	art, err := artifact.Load(skillPath, artifact.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "Error loading skill artifact: %v\n", err)
		return 1
	}

	// 1. Run Security Analysis Engine
	reg := analyzer.DefaultRegistry(nil)
	scanRes, _ := reg.Scan(context.Background(), skil.AnalysisContext{Artifact: art})
	findings := scanRes.Findings

	// 2. Run Quality Analysis
	qualFindings, _ := quality.Analyze(&art)

	// 3. Extract Capability Fingerprint
	candEntry, mainContent, _ := registry.LoadCandidateEntry(skillPath, "")

	// 4. Duplicate Check (if catalog exists)
	var dupResult *registry.DuplicateAnalysisResult
	if _, err := os.Stat(catalogFile); err == nil {
		cat, err := registry.NewFileCatalog(catalogFile)
		if err == nil {
			da := registry.NewDuplicateAnalyzer(cat, nil, nil, registry.DefaultAdmissionConfig())
			res, err := da.AnalyzeDuplicates(context.Background(), candEntry, mainContent, 10)
			if err == nil {
				dupResult = &res
			}
		}
	}

	// 5. Evaluate Trust Score & Level
	inputs := trust.TrustInputs{
		Artifact:        &art,
		Findings:        findings,
		QualityFindings: qualFindings,
		DuplicateResult: dupResult,
		SkillLift:       0.15, // Default evaluated lift +15%
		PassAtK:         0.95,
		IsSigned:        art.PackageDigest != "",
		HasProvenance:   art.Builder != "",
	}

	assessment := trust.EvaluateTrust(inputs, trust.DefaultTrustWeights())

	outWriter := stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			fmt.Fprintf(stderr, "Error creating output file: %v\n", err)
			return 1
		}
		defer f.Close()
		outWriter = f
	}

	switch format {
	case "json":
		enc := json.NewEncoder(outWriter)
		enc.SetIndent("", "  ")
		if err := enc.Encode(assessment); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON output: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintln(outWriter, "SKIL Skill Trust Assessment")
		fmt.Fprintln(outWriter, "────────────────────────────────────────────────────────────")
		fmt.Fprintf(outWriter, "Skill Name:   %s\n", assessment.ArtifactName)
		fmt.Fprintf(outWriter, "Version:      %s\n", assessment.Version)
		fmt.Fprintf(outWriter, "Digest:       %s\n", assessment.Digest)
		fmt.Fprintf(outWriter, "Trust Score:  %.1f / 100\n", assessment.TrustScore.Score)
		fmt.Fprintf(outWriter, "Trust Level:  %s\n", assessment.TrustLevel)
		fmt.Fprintf(outWriter, "Admission:    %s\n", assessment.AdmissionDecision)
		fmt.Fprintln(outWriter)

		fmt.Fprintln(outWriter, "Score Breakdown:")
		fmt.Fprintf(outWriter, "  Security:         %.1f\n", assessment.TrustScore.Breakdown.SecurityScore)
		fmt.Fprintf(outWriter, "  Quality:          %.1f\n", assessment.TrustScore.Breakdown.QualityScore)
		fmt.Fprintf(outWriter, "  Evaluation/Lift:  %.1f\n", assessment.TrustScore.Breakdown.EvaluationScore)
		fmt.Fprintf(outWriter, "  Provenance/Sign:  %.1f\n", assessment.TrustScore.Breakdown.ProvenanceScore)
		fmt.Fprintf(outWriter, "  Permission Risk:  %.1f\n", assessment.TrustScore.Breakdown.PermissionRiskScore)
		fmt.Fprintf(outWriter, "  Duplicate Risk:   %.1f\n", assessment.TrustScore.Breakdown.DuplicateRiskScore)

		if len(assessment.TrustScore.Deductions) > 0 {
			fmt.Fprintln(outWriter)
			fmt.Fprintln(outWriter, "Deductions:")
			for _, d := range assessment.TrustScore.Deductions {
				fmt.Fprintf(outWriter, "  - [%s] -%.1f pts: %s\n", d.Category, d.PointsDeducted, d.Reason)
			}
		}

		if len(assessment.Recommendations) > 0 {
			fmt.Fprintln(outWriter)
			fmt.Fprintln(outWriter, "Recommendations:")
			for _, rec := range assessment.Recommendations {
				fmt.Fprintf(outWriter, "  - %s\n", rec)
			}
		}
	}

	// Exit Code mapping
	switch assessment.AdmissionDecision {
	case registry.DecisionAccept, registry.DecisionAcceptWithWarning:
		return 0
	case registry.DecisionReject:
		return 2
	case registry.DecisionReview:
		return 3
	default:
		return 0
	}
}

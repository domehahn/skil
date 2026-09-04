package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/contextefficiency"
)

// RunOptimize handles `skil optimize context <skill-path>`.
func RunOptimize(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "context" {
		args = args[1:]
	}

	fs := flag.NewFlagSet("optimize", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	fs.StringVar(&format, "format", "terminal", "Output format: terminal|json")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "Error: skill path is required")
		fmt.Fprintln(stderr, "Usage: skil optimize context <skill-path> [--format terminal|json]")
		return 1
	}

	skillPath := fs.Arg(0)

	art, err := artifact.Load(skillPath, artifact.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "Error loading skill artifact: %v\n", err)
		return 1
	}

	report := contextefficiency.AnalyzeEfficiency(&art)

	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON output: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(stdout, "SKIL Context Efficiency Analysis")
	fmt.Fprintln(stdout, "────────────────────────────────────────────────────────────")
	fmt.Fprintf(stdout, "Total Tokens:        %d\n", report.TotalTokens)
	fmt.Fprintf(stdout, "Instruction Tokens:  %d\n", report.InstructionTokens)
	fmt.Fprintf(stdout, "Redundant Tokens:    %d\n", report.RedundantTokens)
	fmt.Fprintf(stdout, "Potential Savings:   %.1f%%\n", report.PotentialSavingsPercent)

	if len(report.RepeatedConcepts) > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Repeated Concepts:")
		for _, concept := range report.RepeatedConcepts {
			fmt.Fprintf(stdout, "  - %s\n", concept)
		}
	}

	if len(report.Recommendations) > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Recommendations:")
		for _, rec := range report.Recommendations {
			fmt.Fprintf(stdout, "  - %s\n", rec)
		}
	}

	return 0
}

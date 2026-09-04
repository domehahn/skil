package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/domehahn/skil/internal/evalharness"
	"gopkg.in/yaml.v3"
)

func RunEval(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	var output string
	var suitePath string

	fs.StringVar(&format, "format", "terminal", "Output format: terminal|json|yaml")
	fs.StringVar(&output, "output", "", "Write output to file path")
	fs.StringVar(&suitePath, "suite", "", "Path to custom evaluation test suite (JSON/YAML)")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return 2
	}

	posArgs := fs.Args()
	if len(posArgs) < 2 || posArgs[0] != "run" {
		fmt.Fprintln(stderr, "Usage: skil eval run <skill-path> [--suite suite.json] [--format terminal|json|yaml] [--output file]")
		return 2
	}

	skillPath := posArgs[1]

	var customSuite *evalharness.TestSuite
	if suitePath != "" {
		data, err := os.ReadFile(suitePath)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to read suite file: %v\n", err)
			return 1
		}
		var s evalharness.TestSuite
		if err := json.Unmarshal(data, &s); err != nil {
			if errY := yaml.Unmarshal(data, &s); errY != nil {
				fmt.Fprintf(stderr, "Error: failed to parse suite file: %v\n", err)
				return 1
			}
		}
		customSuite = &s
	}

	report, err := evalharness.RunEvaluation(context.Background(), skillPath, customSuite)
	if err != nil {
		fmt.Fprintf(stderr, "Error: behavioral evaluation failed: %v\n", err)
		return 1
	}

	var outData []byte
	switch format {
	case "json":
		outData, err = json.MarshalIndent(report, "", "  ")
	case "yaml":
		outData, err = yaml.Marshal(report)
	default:
		outData = []byte(fmt.Sprintf(
			"SKIL Live Behavioral Evaluation Report\n"+
				"Skill Name:                 %s\n"+
				"Pass@1 Rate:                %.2f\n"+
				"Pass@5 Rate:                %.2f\n"+
				"Tool Call Accuracy:         %.2f\n"+
				"Error Recovery Rate:        %.2f\n"+
				"Failure Escalation Safety: %.2f\n"+
				"Composite Lift Score:       %.2f\n",
			report.SkillName, report.PassAt1, report.PassAt5,
			report.ToolCallAccuracy, report.ErrorRecoveryRate,
			report.FailureEscalationSafety, report.CompositeLiftScore,
		))
	}

	if err != nil {
		fmt.Fprintf(stderr, "Error formatting output: %v\n", err)
		return 1
	}

	if output != "" {
		if err := os.WriteFile(output, outData, 0644); err != nil {
			fmt.Fprintf(stderr, "Error writing output file: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintln(stdout, string(outData))
	}

	return 0
}

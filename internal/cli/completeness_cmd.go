package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/domehahn/skil/internal/completeness"
	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

// RunCompleteness executes the `skil completeness <skill-path>` command.
func RunCompleteness(args []string, out, errOut io.Writer) int {
	fs := newFlags("completeness", errOut)
	format := fs.String("format", "terminal", "output format: terminal, json, or yaml")
	outputFile := fs.String("output", "", "output file path")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	skillPath := fs.Arg(0)
	if skillPath == "" {
		fmt.Fprintln(errOut, "error: missing required <skill-path> argument")
		return ExitInput
	}

	findings := []skil.Finding{}
	report, err := completeness.AnalyzeCompleteness(skillPath, findings)
	if err != nil {
		fmt.Fprintf(errOut, "error analyzing completeness for %s: %v\n", skillPath, err)
		return ExitInput
	}

	writer := out
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(errOut, "error creating output file %s: %v\n", *outputFile, err)
			return ExitInput
		}
		defer f.Close()
		writer = f
	}

	switch *format {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(errOut, "error serializing json: %v\n", err)
			return ExitInternal
		}
		fmt.Fprintln(writer, string(data))

	case "yaml":
		data, err := yaml.Marshal(report)
		if err != nil {
			fmt.Fprintf(errOut, "error serializing yaml: %v\n", err)
			return ExitInternal
		}
		fmt.Fprintln(writer, string(data))

	default: // terminal
		fmt.Fprintf(writer, "SKIL Assurance Completeness Report\n")
		fmt.Fprintf(writer, "===================================\n")
		fmt.Fprintf(writer, "Skill Path:         %s\n", report.SkillPath)
		fmt.Fprintf(writer, "Classification:     %s\n", report.Classification)
		fmt.Fprintf(writer, "Completion Ratio:   %.1f%%\n", report.WorkLedger.CompletionRatio()*100)
		fmt.Fprintf(writer, "False Complete Risk: %t\n", report.FalseCompleteRisk)
		fmt.Fprintf(writer, "\nObserver Identity:\n")
		fmt.Fprintf(writer, "  Attestation ID:   %s\n", report.Observer.AttestationIdentity)
		fmt.Fprintf(writer, "  Version:          %s\n", report.Observer.SkilVersion)
		fmt.Fprintf(writer, "  Digest:           %s\n", report.Observer.Digest)
		fmt.Fprintf(writer, "\nWork Accounting Ledger:\n")
		fmt.Fprintf(writer, "  Scheduled Work:   %d\n", report.WorkLedger.Scheduled)
		fmt.Fprintf(writer, "  Processed Work:   %d\n", report.WorkLedger.Processed)
		fmt.Fprintf(writer, "  Transformed Work: %d\n", report.WorkLedger.Transformed)
		fmt.Fprintf(writer, "  Skipped Work:     %d\n", report.WorkLedger.Skipped)
		fmt.Fprintf(writer, "  Unsupported Work: %d\n", report.WorkLedger.Unsupported)
		fmt.Fprintf(writer, "\nResult Commit Protocol:\n")
		fmt.Fprintf(writer, "  Finish Tag:       %s\n", report.CommitProtocol.FinishTag)
		fmt.Fprintf(writer, "  Commit Before Ack: %t\n", report.CommitProtocol.CommitBeforeAck)
		fmt.Fprintf(writer, "  Truncated Output:  %t\n", report.CommitProtocol.TruncatedOutput)
		fmt.Fprintf(writer, "\nResolution Evidence:\n")
		for _, r := range report.Resolutions {
			fmt.Fprintf(writer, "  - [%s] %s (%s): %s\n", r.State, r.TargetSymbol, r.TargetType, r.Reason)
		}
	}

	return ExitOK
}

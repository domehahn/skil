package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/quality"
	"github.com/domehahn/skil/internal/telemetry"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

func RunTelemetry(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("telemetry", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	var output string

	fs.StringVar(&format, "format", "json", "Output format: otlp|json")
	fs.StringVar(&output, "output", "", "Write trace batch output to file path")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return 2
	}

	posArgs := fs.Args()
	if len(posArgs) < 2 || posArgs[0] != "export" {
		fmt.Fprintln(stderr, "Usage: skil telemetry export <skill-path> [--format otlp|json] [--output file]")
		return 2
	}

	skillPath := posArgs[1]

	art, err := artifact.Load(skillPath, artifact.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to load skill artifact: %v\n", err)
		return 1
	}

	reg := analyzer.DefaultRegistry(nil)
	scanRes, _ := reg.Scan(context.Background(), skil.AnalysisContext{Artifact: art})
	qualFindings, _ := quality.Analyze(&art)

	inputs := trust.TrustInputs{
		Artifact:        &art,
		Findings:        scanRes.Findings,
		QualityFindings: qualFindings,
		SkillLift:       0.15,
		PassAtK:         0.95,
	}

	assessment := trust.EvaluateTrust(inputs, trust.DefaultTrustWeights())

	span := telemetry.BuildTrustTraceSpan(assessment)
	outData, err := telemetry.ExportTraceBatch([]telemetry.OTelSpanFormat{span})
	if err != nil {
		fmt.Fprintf(stderr, "Error exporting telemetry trace batch: %v\n", err)
		return 1
	}

	if output != "" {
		if err := os.WriteFile(output, outData, 0644); err != nil {
			fmt.Fprintf(stderr, "Error writing telemetry output file: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintln(stdout, string(outData))
	}

	return 0
}

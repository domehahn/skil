package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/card"
	"github.com/domehahn/skil/internal/quality"
	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

// RunCard handles `skil card <skill-path>`.
func RunCard(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("card", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	var output string

	fs.StringVar(&format, "format", "yaml", "Output format: yaml|markdown|json")
	fs.StringVar(&output, "output", "", "Path to output file")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "Error: skill path is required")
		fmt.Fprintln(stderr, "Usage: skil card <skill-path> [--format yaml|markdown|json]")
		return 1
	}

	skillPath := fs.Arg(0)

	art, err := artifact.Load(skillPath, artifact.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "Error loading skill artifact: %v\n", err)
		return 1
	}

	reg := analyzer.DefaultRegistry(nil)
	scanRes, _ := reg.Scan(context.Background(), skil.AnalysisContext{Artifact: art})
	findings := scanRes.Findings
	qualFindings, _ := quality.Analyze(&art)

	candEntry, _, _ := registry.LoadCandidateEntry(skillPath, "")
	caps := candEntry.Capabilities

	inputs := trust.TrustInputs{
		Artifact:        &art,
		Findings:        findings,
		QualityFindings: qualFindings,
		IsSigned:        art.PackageDigest != "",
		HasProvenance:   art.Builder != "",
	}
	assessment := trust.EvaluateTrust(inputs, trust.DefaultTrustWeights())

	skillCard := card.Generate(&art, &assessment, caps, findings)

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
		data, err := skillCard.ToJSON()
		if err != nil {
			fmt.Fprintf(stderr, "Error generating JSON card: %v\n", err)
			return 1
		}
		_, _ = outWriter.Write(data)
		_, _ = outWriter.Write([]byte("\n"))
	case "markdown":
		_, _ = outWriter.Write([]byte(skillCard.ToMarkdown()))
	default:
		data, err := skillCard.ToYAML()
		if err != nil {
			fmt.Fprintf(stderr, "Error generating YAML card: %v\n", err)
			return 1
		}
		_, _ = outWriter.Write(data)
	}

	return 0
}

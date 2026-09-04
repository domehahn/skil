package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/attackpath"
	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/pkg/skil"
)

// RunGraph handles `skil graph capabilities|attack-path <skill-paths...>`.
func RunGraph(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Error: subcommand (capabilities|attack-path) required")
		fmt.Fprintln(stderr, "Usage: skil graph capabilities|attack-path <skill-paths...>")
		return 1
	}

	subCmd := args[0]
	args = args[1:]

	fs := flag.NewFlagSet("graph "+subCmd, flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	fs.StringVar(&format, "format", "terminal", "Output format: terminal|json")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "Error: at least one skill path is required")
		return 1
	}

	g := attackpath.NewCapabilityGraph()
	reg := analyzer.DefaultRegistry(nil)

	for _, skillPath := range fs.Args() {
		art, err := artifact.Load(skillPath, artifact.Options{})
		if err != nil {
			fmt.Fprintf(stderr, "Error loading %s: %v\n", skillPath, err)
			continue
		}
		scanRes, _ := reg.Scan(context.Background(), skil.AnalysisContext{Artifact: art})
		candEntry, _, _ := registry.LoadCandidateEntry(skillPath, "")
		caps := candEntry.Capabilities

		g.AddSkillCapabilities(art.Name, caps, scanRes.Findings)
	}

	result := attackpath.AnalyzeCrossSkillAttackPaths(g)

	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON output: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(stdout, "SKIL Capability & Attack Path Graph")
	fmt.Fprintln(stdout, "────────────────────────────────────────────────────────────")
	fmt.Fprintf(stdout, "Total Graph Nodes: %d\n", len(g.Nodes))
	fmt.Fprintf(stdout, "Total Graph Edges: %d\n", len(g.Edges))
	fmt.Fprintf(stdout, "Risky Paths:       %t\n", result.HasRiskyPath)

	if len(result.Findings) > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Discovered Attack Paths:")
		for _, f := range result.Findings {
			fmt.Fprintf(stdout, "  - [%s] %s: %s\n", f.Severity, f.RuleID, f.Message)
		}
	} else {
		fmt.Fprintln(stdout, "No cross-skill exfiltration attack paths discovered.")
	}

	return 0
}

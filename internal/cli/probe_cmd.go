package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/domehahn/skil/internal/redteam"
	"gopkg.in/yaml.v3"
)

func RunProbe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	var output string
	var payloadCat string

	fs.StringVar(&format, "format", "terminal", "Output format: terminal|json|yaml")
	fs.StringVar(&output, "output", "", "Write output to file path")
	fs.StringVar(&payloadCat, "payloads", "", "Comma-separated attack categories (e.g. INDIRECT_INJECTION,OBFUSCATION_ENCODING)")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return 2
	}

	posArgs := fs.Args()
	if len(posArgs) < 1 {
		fmt.Fprintln(stderr, "Usage: skil probe <skill-path> [--payloads <categories>] [--format terminal|json|yaml] [--output file]")
		return 2
	}

	skillPath := posArgs[0]

	var categories []redteam.AttackCategory
	if payloadCat != "" {
		parts := strings.Split(payloadCat, ",")
		for _, p := range parts {
			categories = append(categories, redteam.AttackCategory(strings.TrimSpace(p)))
		}
	}

	report, err := redteam.ProbeSkill(context.Background(), skillPath, categories)
	if err != nil {
		fmt.Fprintf(stderr, "Error: red-teaming probe failed: %v\n", err)
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
			"SKIL Adversarial Red-Teaming Probe Report\n"+
				"Skill Name:                         %s\n"+
				"Vulnerability Exploitability Score: %.2f\n"+
				"Total Probes Executed:             %d\n"+
				"Exploited Probes:                  %d\n"+
				"Total Findings Emitted:            %d\n",
			report.SkillName, report.VulnerabilityExploitabilityScore,
			report.TotalProbes, report.ExploitedProbes, len(report.Findings),
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

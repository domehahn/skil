package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

func Write(w io.Writer, format string, result skil.ScanResult) error {
	switch strings.ToLower(format) {
	case "json":
		return writeJSON(w, result)
	case "sarif":
		return writeJSON(w, SARIF(result))
	case "markdown", "md":
		return writeMarkdown(w, result)
	case "terminal", "":
		return writeTerminal(w, result)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
func writeTerminal(w io.Writer, r skil.ScanResult) error {
	fmt.Fprintf(w, "skil security report\n\nArtifact: %s\nDigest:   sha256:%s\nStatus:   %s\nVerdict:  %s\nRisk:     %d/100\nCoverage: ", r.Artifact.Name, r.Artifact.Digest, r.Status, r.Verdict, r.RiskScore)
	keys := sortedCoverage(r.Coverage)
	for i, key := range keys {
		if i > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprintf(w, "%s=%s", key, r.Coverage[key])
	}
	fmt.Fprintf(w, "\n\nFindings (%d)\n", len(r.Findings))
	for _, f := range r.Findings {
		suppressed := ""
		if f.Suppressed {
			suppressed = " [suppressed]"
		}
		fmt.Fprintf(w, "- %s %s%s: %s (%s:%d)\n", f.Severity, f.RuleID, suppressed, f.Title, f.Location.File, f.Location.StartLine)
	}
	return nil
}
func writeMarkdown(w io.Writer, r skil.ScanResult) error {
	fmt.Fprintf(w, "# skil security report\n\n- Artifact: `%s`\n- Digest: `sha256:%s`\n- Status: **%s**\n- Verdict: **%s**\n- Risk: **%d/100**\n\n## Findings\n\n", r.Artifact.Name, r.Artifact.Digest, r.Status, r.Verdict, r.RiskScore)
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	fmt.Fprintln(w, "| Severity | Rule | Finding | Location |\n|---|---|---|---|")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "| %s | `%s` | %s | `%s:%d` |\n", f.Severity, f.RuleID, escape(f.Title), f.Location.File, f.Location.StartLine)
	}
	return nil
}
func sortedCoverage(c map[string]skil.CoverageState) []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func escape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

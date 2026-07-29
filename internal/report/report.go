package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

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
	fmt.Fprintf(w, "skil security report\n\nArtifact: %s\nDigest:   sha256:%s\nStatus:   %s\nVerdict:  %s\nRisk:     %d/100\nInspection: %.1f%% (%d/%d applicable work items)\nCoverage: ",
		safeDisplay(r.Artifact.Name), r.Artifact.Digest, r.Status, r.Verdict, r.RiskScore,
		r.Completeness.Completeness*100, r.Completeness.Completed, r.Completeness.Applicable)
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
			suppressed = " [suppressed"
			if f.SuppressionReason != "" {
				suppressed += ": " + safeDisplay(f.SuppressionReason)
			}
			suppressed += "]"
		}
		fmt.Fprintf(w, "- %s %s%s: %s (%s:%d)\n", f.Severity, safeDisplay(f.RuleID), suppressed,
			safeDisplay(f.Title), safeDisplay(f.Location.File), f.Location.StartLine)
	}
	return nil
}
func writeMarkdown(w io.Writer, r skil.ScanResult) error {
	fmt.Fprintf(w, "# skil security report\n\n- Artifact: `%s`\n- Digest: `sha256:%s`\n- Status: **%s**\n- Verdict: **%s**\n- Risk: **%d/100**\n- Inspection completeness: **%.1f%%** (%d/%d applicable work items)\n\n## Findings\n\n",
		MarkdownText(r.Artifact.Name), r.Artifact.Digest, r.Status, r.Verdict, r.RiskScore,
		r.Completeness.Completeness*100, r.Completeness.Completed, r.Completeness.Applicable)
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	fmt.Fprintln(w, "| Severity | Rule | Finding | Location |\n|---|---|---|---|")
	for _, f := range r.Findings {
		title := MarkdownText(f.Title)
		if f.Suppressed {
			title += " _(suppressed"
			if f.SuppressionReason != "" {
				title += ": " + MarkdownText(f.SuppressionReason)
			}
			title += ")_"
		}
		fmt.Fprintf(w, "| %s | `%s` | %s | `%s:%d` |\n", f.Severity, MarkdownText(f.RuleID),
			title, MarkdownText(f.Location.File), f.Location.StartLine)
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
func MarkdownText(s string) string {
	return strings.NewReplacer("\\", "\\\\", "|", "\\|", "`", "\\`").Replace(safeDisplay(s))
}

// safeDisplay strips terminal/format controls from attacker-controlled names,
// paths, and provider text before they reach a human-facing renderer.
func safeDisplay(s string) string {
	var out strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			out.WriteRune(' ')
			continue
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			out.WriteRune('\uFFFD')
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

package lint

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/domehahn/skil/internal/report"
	"github.com/domehahn/skil/pkg/skil"
)

func Write(writer io.Writer, format string, result Result) error {
	switch strings.ToLower(format) {
	case "terminal", "":
		return writeTerminal(writer, result)
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case "markdown", "md":
		return writeMarkdown(writer, result)
	case "sarif":
		return writeSARIF(writer, result)
	default:
		return fmt.Errorf("unsupported lint format %q", format)
	}
}

func writeTerminal(writer io.Writer, result Result) error {
	fmt.Fprintf(writer, "skil lint report\n\nArtifact: %s\nDigest:   sha256:%s\nStatus:   %s\nProfile:  %s\nStrict:   %t\nIssues:   %d errors, %d warnings, %d notes\n\n",
		display(result.Artifact.Name), result.Artifact.Digest, result.Status, result.Profile, result.Strict,
		result.Summary.Errors, result.Summary.Warnings, result.Summary.Notes)
	for _, issue := range result.Issues {
		fmt.Fprintf(writer, "- %s %s: %s (%s:%d)\n", strings.ToUpper(string(issue.Level)),
			display(issue.RuleID), display(issue.Title), display(issue.Location.File), issue.Location.StartLine)
	}
	return nil
}

func writeMarkdown(writer io.Writer, result Result) error {
	fmt.Fprintf(writer, "# skil lint report\n\n- Artifact: `%s`\n- Digest: `sha256:%s`\n- Status: **%s**\n- Profile: **%s**\n- Strict: **%t**\n- Issues: **%d errors, %d warnings, %d notes**\n\n",
		report.MarkdownText(result.Artifact.Name), result.Artifact.Digest, result.Status, result.Profile, result.Strict,
		result.Summary.Errors, result.Summary.Warnings, result.Summary.Notes)
	if len(result.Issues) == 0 {
		_, err := fmt.Fprintln(writer, "No lint issues.")
		return err
	}
	fmt.Fprintln(writer, "| Level | Rule | Issue | Location |\n|---|---|---|---|")
	for _, issue := range result.Issues {
		fmt.Fprintf(writer, "| %s | `%s` | %s | `%s:%d` |\n", issue.Level,
			report.MarkdownText(issue.RuleID), report.MarkdownText(issue.Title),
			report.MarkdownText(issue.Location.File), issue.Location.StartLine)
	}
	return nil
}

func writeSARIF(writer io.Writer, result Result) error {
	findings := make([]skil.Finding, 0, len(result.Issues))
	for _, issue := range result.Issues {
		severity := skil.SeverityInfo
		if issue.Level == LevelError {
			severity = skil.SeverityHigh
		} else if issue.Level == LevelWarning {
			severity = skil.SeverityMedium
		}
		findings = append(findings, skil.Finding{
			ID: issue.Fingerprint, RuleID: issue.RuleID, Category: "lint", Severity: severity,
			Confidence: 1, Title: issue.Title, Message: issue.Message, Description: issue.Message,
			Location: issue.Location, Remediation: issue.Remediation, Fingerprint: issue.Fingerprint,
		})
	}
	scan := skil.ScanResult{
		SchemaVersion: result.SchemaVersion, Artifact: result.Artifact, Status: result.Status,
		Verdict: skil.VerdictClear, Findings: findings, Scanners: []string{"skil.lint"},
		GeneratedAt: result.GeneratedAt,
	}
	if result.Status == skil.StatusFail {
		scan.Verdict = skil.VerdictBlock
	} else if result.Status == skil.StatusWarn {
		scan.Verdict = skil.VerdictReview
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report.SARIF(scan))
}

func display(value string) string {
	var out strings.Builder
	for _, char := range value {
		if char == '\n' || char == '\r' || char == '\t' {
			out.WriteRune(' ')
		} else if unicode.IsControl(char) || unicode.In(char, unicode.Cf) {
			out.WriteRune('\uFFFD')
		} else {
			out.WriteRune(char)
		}
	}
	return out.String()
}

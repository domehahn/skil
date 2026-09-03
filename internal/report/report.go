package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/domehahn/skil/pkg/skil"
)

const terminalWidth = 100

func Write(w io.Writer, format string, result skil.ScanResult) error {
	switch strings.ToLower(format) {
	case "json":
		return writeJSON(w, result)
	case "sarif":
		return writeJSON(w, SARIF(result))
	case "markdown", "md":
		return writeMarkdown(w, result)
	case "html":
		return writeHTML(w, result)
	case "interactive-html", "interactive":
		return writeInteractiveWorkbench(w, result)
	case "terminal", "":
		return writeTerminal(w, result)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

// WriteCompact preserves the terse terminal representation for scripting and
// users who explicitly prefer one finding per line.
func WriteCompact(w io.Writer, r skil.ScanResult) error {
	fmt.Fprintf(w, "skil security report\n\nArtifact: %s\nDigest:   sha256:%s\nStatus:   %s\nVerdict:  %s\nRisk:     %d/100\nInspection: %.1f%% (%d/%d applicable work items)\nCoverage: ",
		safeDisplay(r.Artifact.Name), r.Artifact.Digest, r.Status, r.Verdict, r.RiskScore,
		r.Completeness.Completeness*100, r.Completeness.Completed, r.Completeness.Applicable)
	for index, key := range sortedCoverage(r.Coverage) {
		if index > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprintf(w, "%s=%s", key, r.Coverage[key])
	}
	fmt.Fprintf(w, "\n\nFindings (%d)\n", len(r.Findings))
	for _, finding := range sortedFindings(r.Findings) {
		suppressed := suppressionLabel(finding)
		fmt.Fprintf(w, "- %s %s%s: %s (%s:%d)\n", finding.Severity, safeDisplay(finding.RuleID), suppressed,
			safeDisplay(finding.Title), safeDisplay(finding.Location.File), finding.Location.StartLine)
	}
	return nil
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeTerminal(w io.Writer, r skil.ScanResult) error {
	fmt.Fprintln(w, "SKIL SECURITY REPORT")
	fmt.Fprintln(w, strings.Repeat("=", 20))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "ARTIFACT")
	fmt.Fprintf(w, "  Artifact     %s\n", boundedDisplay(r.Artifact.Name, 78))
	fmt.Fprintf(w, "  Source       %s\n", boundedDisplay(r.Artifact.Source, 78))
	fmt.Fprintf(w, "  Digest       sha256:%s\n", safeDisplay(r.Artifact.Digest))
	if !r.Artifact.Timestamp.IsZero() {
		fmt.Fprintf(w, "  Scanned      %s\n", r.Artifact.Timestamp.UTC().Format("2006-01-02T15:04:05Z"))
	}

	fmt.Fprintln(w, "\nRISK ASSESSMENT")
	fmt.Fprintf(w, "  Status       %s\n", r.Status)
	fmt.Fprintf(w, "  Verdict      %s\n", r.Verdict)
	fmt.Fprintf(w, "  Risk         %d/100 (%s maximum)\n", r.RiskScore, r.Maximum)

	fmt.Fprintf(w, "\nCOMPONENTS (%d)\n", len(r.Artifact.Files))
	fmt.Fprintf(w, "  %-58s %-12s %7s %10s\n", "PATH", "TYPE", "LINES", "EXECUTABLE")
	var transcoded []skil.File
	for _, file := range sortedFiles(r.Artifact.Files) {
		fmt.Fprintf(w, "  %-58s %-12s %7d %10t\n",
			boundedDisplay(file.Path, 58), componentType(file.Path), lineCount(file.Data), file.Executable)
		if file.Encoding != "" && file.Encoding != "utf-8" && file.Encoding != "binary" {
			transcoded = append(transcoded, file)
		}
	}
	if len(r.Artifact.Files) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	if len(transcoded) > 0 {
		fmt.Fprintln(w, "\nENCODING NOTES")
		fmt.Fprintln(w, "  The following files were not UTF-8 and were transcoded to canonical")
		fmt.Fprintln(w, "  UTF-8 before analysis; findings below reference the transcoded text.")
		for _, file := range transcoded {
			fmt.Fprintf(w, "  %-58s %s\n", boundedDisplay(file.Path, 58), file.Encoding)
		}
	}
	if r.DerivedViews != nil && (len(r.DerivedViews.Views) > 0 || !r.DerivedViews.Complete) {
		fmt.Fprintln(w, "\nDERIVED SECURITY VIEWS")
		fmt.Fprintf(w, "  Views         %d\n", len(r.DerivedViews.Views))
		fmt.Fprintf(w, "  Complete      %t\n", r.DerivedViews.Complete)
		fmt.Fprintf(w, "  Bytes         %d\n", r.DerivedViews.Bytes)
		fmt.Fprintf(w, "  Maximum depth %d\n", r.DerivedViews.MaxDepth)
		if len(r.DerivedViews.Limitations) > 0 {
			fmt.Fprintf(w, "  Limitations   %s\n", boundedDisplay(strings.Join(r.DerivedViews.Limitations, "; "), 82))
		}
	}

	findings := sortedFindings(r.Findings)
	fmt.Fprintf(w, "\nFINDINGS (%d)\n", len(findings))
	if len(findings) == 0 {
		fmt.Fprintln(w, "  No findings.")
	}
	for index, finding := range findings {
		fmt.Fprintf(w, "\n  %d. [%s] %s — %s%s\n", index+1, finding.Severity,
			boundedDisplay(finding.RuleID, 32), boundedDisplay(finding.Title, 48), suppressionLabel(finding))
		writeWrapped(w, "Location", fmt.Sprintf("%s:%d", finding.Location.File, finding.Location.StartLine))
		if finding.Category != "" {
			writeWrapped(w, "Category", finding.Category)
		}
		writeWrapped(w, "Confidence", fmt.Sprintf("%.0f%%", finding.Confidence*100))
		writeWrapped(w, "Description", firstNonEmpty(finding.Description, finding.Message))
		if finding.Message != "" && finding.Message != finding.Description {
			writeWrapped(w, "Message", finding.Message)
		}
		if len(finding.Evidence) > 0 {
			writeWrapped(w, "Evidence", evidenceText(finding.Evidence))
		}
		if finding.Remediation != "" {
			writeWrapped(w, "Remediation", finding.Remediation)
		}
		if len(finding.References) > 0 {
			writeWrapped(w, "References", strings.Join(finding.References, ", "))
		}
		if finding.Fingerprint != "" {
			writeWrapped(w, "Fingerprint", finding.Fingerprint)
		}
	}

	fmt.Fprintln(w, "\nINSPECTION COMPLETENESS")
	fmt.Fprintf(w, "  Coverage      %.1f%%\n", r.Completeness.Completeness*100)
	fmt.Fprintf(w, "  Applicable    %d\n", r.Completeness.Applicable)
	fmt.Fprintf(w, "  Completed     %d\n", r.Completeness.Completed)
	fmt.Fprintf(w, "  Skipped       %d\n", r.Completeness.Skipped)
	fmt.Fprintf(w, "  Failed        %d\n", r.Completeness.Failed)
	fmt.Fprintf(w, "  Out of scope  %d\n", r.Completeness.OutOfScope)

	// Distinct from inspection completeness above: a file can have every
	// applicable analyzer report "completed" (nothing was skipped) while
	// its actual content stayed opaque to analysis — e.g. a binary format
	// with no applicable text analyzer to skip in the first place. This
	// answers "was the content visible", not "did the analyzers run".
	if r.Analyzable.Files > 0 {
		fmt.Fprintln(w, "\nANALYZABILITY")
		fmt.Fprintf(w, "  Coverage      %.1f%%\n", r.Analyzable.Coverage*100)
		fmt.Fprintf(w, "  Files         %d\n", r.Analyzable.Files)
		fmt.Fprintf(w, "  Full          %d\n", r.Analyzable.Full)
		fmt.Fprintf(w, "  Partial       %d\n", r.Analyzable.Partial)
		fmt.Fprintf(w, "  Opaque        %d\n", r.Analyzable.Opaque)
		if r.Analyzable.Opaque > 0 {
			for _, record := range sortedAnalyzability(r.Analyzability) {
				if record.State != skil.AnalyzabilityOpaque {
					continue
				}
				label := record.BinaryKind
				if label == "" {
					label = "unrecognized binary"
				}
				fmt.Fprintf(w, "    %-58s %s\n", boundedDisplay(record.Path, 58), label)
			}
		}
	}

	if len(r.Budget.Exceeded) > 0 {
		fmt.Fprintln(w, "\nANALYSIS BUDGET (exceeded)")
		fmt.Fprintf(w, "  %-20s %14s %14s\n", "DIMENSION", "USED", "LIMIT")
		fmt.Fprintf(w, "  %-20s %14d %14d\n", "raw_bytes", r.Budget.RawBytes.Used, r.Budget.RawBytes.Limit)
		fmt.Fprintf(w, "  %-20s %14d %14d\n", "expanded_bytes", r.Budget.ExpandedBytes.Used, r.Budget.ExpandedBytes.Limit)
		fmt.Fprintf(w, "  %-20s %14d %14d\n", "findings", r.Budget.Findings.Used, r.Budget.Findings.Limit)
		fmt.Fprintf(w, "  %-20s %14d %14d\n", "inspection_events", r.Budget.InspectionEvents.Used, r.Budget.InspectionEvents.Limit)
		fmt.Fprintf(w, "  %-20s %14d %14d\n", "derived_views", r.Budget.DerivedViews.Used, r.Budget.DerivedViews.Limit)
		fmt.Fprintf(w, "  %-20s %14d %14d\n", "derived_depth", r.Budget.DerivedDepth.Used, r.Budget.DerivedDepth.Limit)
		fmt.Fprintf(w, "  %-20s %14d %14d\n", "derived_bytes", r.Budget.DerivedBytes.Used, r.Budget.DerivedBytes.Limit)
		fmt.Fprintf(w, "  %-20s %11dms %11dms\n", "wall_time", r.Budget.WallTime.Used, r.Budget.WallTime.Limit)
		fmt.Fprintf(w, "  Exceeded: %s\n", strings.Join(r.Budget.Exceeded, ", "))
	}

	if r.Closure != nil {
		fmt.Fprintln(w, "\nASSURANCE CLOSURE")
		fmt.Fprintf(w, "  %-20s %s\n", "State", r.Closure.State)
		fmt.Fprintf(w, "  %-20s %t\n", "Complete", r.Closure.Complete)
		fmt.Fprintf(w, "  %-20s %t\n", "Verified", r.Closure.Verified)
		fmt.Fprintf(w, "  %-20s %d\n", "Nodes", len(r.Closure.Nodes))
		fmt.Fprintf(w, "  %-20s %d\n", "Required", r.Closure.RequiredNodes)
		fmt.Fprintf(w, "  %-20s %d\n", "Unresolved", r.Closure.UnresolvedNodes)
		fmt.Fprintf(w, "  %-20s %d\n", "Blocking findings", r.Closure.BlockingFindings)
		fmt.Fprintf(w, "  %-20s %d\n", "Maximum depth", r.Closure.MaxDepth)
		fmt.Fprintf(w, "  %-20s %s\n", "Closure digest", r.Closure.Digest)
		for _, node := range r.Closure.Nodes {
			if !node.Required || node.Resolved && node.Analyzed && node.Verdict != string(skil.VerdictBlock) {
				continue
			}
			fmt.Fprintf(w, "  ! %-18s %-48s status=%s verification=%s\n", node.Kind, boundedDisplay(node.Source, 48), node.ScanStatus, node.Verification)
		}
	}

	if len(r.References) > 0 {
		fmt.Fprintln(w, "\nTRANSITIVE REFERENCES")
		for _, node := range r.References {
			status := "skipped"
			detail := node.SkipReason
			if node.Fetched {
				status = "fetched"
				detail = "sha256:" + node.Digest
				if node.Scan != nil {
					detail += " status=" + string(node.Scan.Status)
				}
			}
			fmt.Fprintf(w, "  [depth %d] %-6s %-58s %s\n", node.Depth, status, boundedDisplay(node.URL, 58), detail)
		}
	}

	fmt.Fprintln(w, "\nANALYZER STATUS")
	fmt.Fprintf(w, "  %-34s %-14s %5s %-35s\n", "ANALYZER", "STATUS", "ITEMS", "REASON")
	statuses := analyzerStatuses(r.Inspection)
	if len(statuses) == 0 {
		fmt.Fprintln(w, "  (no inspection ledger)")
	}
	for _, status := range statuses {
		fmt.Fprintf(w, "  %-34s %-14s %5d %-35s\n", boundedDisplay(status.Name, 34), status.Outcome,
			status.Items, boundedDisplay(status.Reason, 35))
	}

	fmt.Fprintln(w, "\nCOVERAGE")
	fmt.Fprintf(w, "  %-32s %s\n", "ANALYSIS", "STATE")
	for _, key := range sortedCoverage(r.Coverage) {
		fmt.Fprintf(w, "  %-32s %s\n", boundedDisplay(key, 32), r.Coverage[key])
	}

	fmt.Fprintln(w, "\nLIMITATIONS & DIAGNOSTICS")
	limitations := limitationLines(r)
	if len(limitations) == 0 {
		fmt.Fprintln(w, "  None.")
	}
	for _, limitation := range limitations {
		writeWrapped(w, "-", limitation)
	}
	return nil
}

func writeMarkdown(w io.Writer, r skil.ScanResult) error {
	fmt.Fprintf(w, "# skil security report\n\n- Artifact: `%s`\n- Source: `%s`\n- Digest: `sha256:%s`\n",
		MarkdownText(r.Artifact.Name), MarkdownText(r.Artifact.Source), r.Artifact.Digest)
	if !r.Artifact.Timestamp.IsZero() {
		fmt.Fprintf(w, "- Scanned: `%s`\n", r.Artifact.Timestamp.UTC().Format("2006-01-02T15:04:05Z"))
	}
	fmt.Fprintf(w, "\n## Risk assessment\n\n- Status: **%s**\n- Verdict: **%s**\n- Risk: **%d/100**\n- Maximum severity: **%s**\n\n",
		r.Status, r.Verdict, r.RiskScore, r.Maximum)

	fmt.Fprintf(w, "## Components (%d)\n\n| Path | Type | Lines | Executable |\n|---|---|---:|---:|\n", len(r.Artifact.Files))
	for _, file := range sortedFiles(r.Artifact.Files) {
		fmt.Fprintf(w, "| `%s` | %s | %d | %t |\n", MarkdownText(file.Path),
			MarkdownText(componentType(file.Path)), lineCount(file.Data), file.Executable)
	}
	if r.DerivedViews != nil && (len(r.DerivedViews.Views) > 0 || !r.DerivedViews.Complete) {
		fmt.Fprintf(w, "\n## Derived security views\n\n- Views: %d\n- Complete: **%t**\n- Bytes: %d\n- Maximum depth: %d\n",
			len(r.DerivedViews.Views), r.DerivedViews.Complete, r.DerivedViews.Bytes, r.DerivedViews.MaxDepth)
		for _, limitation := range r.DerivedViews.Limitations {
			fmt.Fprintf(w, "- Limitation: %s\n", MarkdownText(limitation))
		}
	}

	fmt.Fprintln(w, "\n## Findings")
	findings := sortedFindings(r.Findings)
	if len(findings) == 0 {
		fmt.Fprintln(w, "\nNo findings.")
	} else {
		for _, finding := range findings {
			fmt.Fprintf(w, "\n### %s · `%s` · %s%s\n\n", finding.Severity, MarkdownText(finding.RuleID),
				MarkdownText(finding.Title), suppressionLabel(finding))
			fmt.Fprintf(w, "- Location: `%s:%d`\n", MarkdownText(finding.Location.File), finding.Location.StartLine)
			if finding.Category != "" {
				fmt.Fprintf(w, "- Category: %s\n", MarkdownText(finding.Category))
			}
			fmt.Fprintf(w, "- Confidence: %.0f%%\n", finding.Confidence*100)
			fmt.Fprintf(w, "- Description: %s\n", MarkdownText(firstNonEmpty(finding.Description, finding.Message)))
			if finding.Message != "" && finding.Message != finding.Description {
				fmt.Fprintf(w, "- Message: %s\n", MarkdownText(finding.Message))
			}
			if len(finding.Evidence) > 0 {
				fmt.Fprintf(w, "- Evidence: `%s`\n", MarkdownText(evidenceText(finding.Evidence)))
			}
			if finding.Remediation != "" {
				fmt.Fprintf(w, "- Remediation: %s\n", MarkdownText(finding.Remediation))
			}
			if len(finding.References) > 0 {
				fmt.Fprintf(w, "- References: %s\n", MarkdownText(strings.Join(finding.References, ", ")))
			}
			if finding.Fingerprint != "" {
				fmt.Fprintf(w, "- Fingerprint: `%s`\n", MarkdownText(finding.Fingerprint))
			}
		}
	}

	fmt.Fprintf(w, "\n## Inspection completeness\n\n- Coverage: **%.1f%%**\n- Applicable: %d\n- Completed: %d\n- Skipped: %d\n- Failed: %d\n- Out of scope: %d\n",
		r.Completeness.Completeness*100, r.Completeness.Applicable, r.Completeness.Completed,
		r.Completeness.Skipped, r.Completeness.Failed, r.Completeness.OutOfScope)
	if r.Closure != nil {
		fmt.Fprintf(w, "\n## Assurance closure\n\n- State: **%s**\n- Complete: **%t**\n- Verified: **%t**\n- Nodes: %d\n- Required: %d\n- Unresolved: %d\n- Blocking findings: %d\n- Maximum depth: %d\n- Closure digest: `%s`\n",
			r.Closure.State, r.Closure.Complete, r.Closure.Verified, len(r.Closure.Nodes), r.Closure.RequiredNodes,
			r.Closure.UnresolvedNodes, r.Closure.BlockingFindings, r.Closure.MaxDepth, r.Closure.Digest)
	}

	fmt.Fprintln(w, "\n## Analysis coverage\n\n| Analysis | State |\n|---|---|")
	for _, key := range sortedCoverage(r.Coverage) {
		fmt.Fprintf(w, "| %s | %s |\n", MarkdownText(key), r.Coverage[key])
	}
	fmt.Fprintln(w, "\n## Limitations and diagnostics")
	limitations := limitationLines(r)
	if len(limitations) == 0 {
		fmt.Fprintln(w, "\nNone.")
	}
	for _, limitation := range limitations {
		fmt.Fprintf(w, "\n- %s", MarkdownText(limitation))
	}
	if len(limitations) > 0 {
		fmt.Fprintln(w)
	}
	return nil
}

type analyzerStatus struct {
	Name    string
	Outcome skil.InspectionOutcome
	Items   int
	Reason  string
}

func analyzerStatuses(items []skil.InspectionWorkItem) []analyzerStatus {
	byName := map[string]*analyzerStatus{}
	rank := map[skil.InspectionOutcome]int{
		skil.InspectionOutOfScope: 0, skil.InspectionCompleted: 1,
		skil.InspectionSkipped: 2, skil.InspectionFailed: 3,
	}
	for _, item := range items {
		status := byName[item.Analyzer]
		if status == nil {
			status = &analyzerStatus{Name: item.Analyzer, Outcome: item.Outcome}
			byName[item.Analyzer] = status
		}
		status.Items++
		if rank[item.Outcome] > rank[status.Outcome] {
			status.Outcome = item.Outcome
		}
		if status.Reason == "" && item.Reason != "" && item.Outcome != skil.InspectionOutOfScope {
			status.Reason = item.Reason
		}
	}
	out := make([]analyzerStatus, 0, len(byName))
	for _, status := range byName {
		out = append(out, *status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func limitationLines(r skil.ScanResult) []string {
	var out []string
	for _, key := range sortedCoverage(r.Coverage) {
		if r.Coverage[key] != skil.CoverageCompleted {
			out = append(out, fmt.Sprintf("%s analysis: %s", key, r.Coverage[key]))
		}
	}
	diagnostics := append([]skil.Diagnostic(nil), r.Diagnostics...)
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].Component != diagnostics[j].Component {
			return diagnostics[i].Component < diagnostics[j].Component
		}
		if diagnostics[i].Level != diagnostics[j].Level {
			return diagnostics[i].Level < diagnostics[j].Level
		}
		return diagnostics[i].Message < diagnostics[j].Message
	})
	for _, diagnostic := range diagnostics {
		out = append(out, fmt.Sprintf("%s [%s]: %s", diagnostic.Component, diagnostic.Level, diagnostic.Message))
	}
	return out
}

func sortedFindings(findings []skil.Finding) []skil.Finding {
	out := append([]skil.Finding(nil), findings...)
	rank := map[skil.Severity]int{
		skil.SeverityCritical: 0, skil.SeverityHigh: 1, skil.SeverityMedium: 2,
		skil.SeverityLow: 3, skil.SeverityInfo: 4,
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if rank[left.Severity] != rank[right.Severity] {
			return rank[left.Severity] < rank[right.Severity]
		}
		if left.Location.File != right.Location.File {
			return left.Location.File < right.Location.File
		}
		if left.Location.StartLine != right.Location.StartLine {
			return left.Location.StartLine < right.Location.StartLine
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		return left.Fingerprint < right.Fingerprint
	})
	return out
}

func sortedFiles(files []skil.File) []skil.File {
	out := append([]skil.File(nil), files...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func sortedAnalyzability(records []skil.AnalyzabilityRecord) []skil.AnalyzabilityRecord {
	out := append([]skil.AnalyzabilityRecord(nil), records...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func sortedCoverage(coverage map[string]skil.CoverageState) []string {
	keys := make([]string, 0, len(coverage))
	for key := range coverage {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func componentType(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "skill.md":
		return "skill"
	case "pyproject.toml", "requirements.txt", "package.json", "package-lock.json", "go.mod":
		return "dependency"
	}
	extension := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	if extension == "" {
		return "file"
	}
	return boundedDisplay(extension, 12)
}

func lineCount(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	count := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		count++
	}
	return count
}

func evidenceText(evidence map[string]any) string {
	data, err := json.Marshal(evidence)
	if err != nil {
		return "(unrenderable evidence)"
	}
	return boundedDisplay(string(data), 1200)
}

func suppressionLabel(finding skil.Finding) string {
	if !finding.Suppressed {
		return ""
	}
	label := " [suppressed"
	if finding.SuppressionReason != "" {
		label += ": " + boundedDisplay(finding.SuppressionReason, 80)
	}
	return label + "]"
}

func writeWrapped(w io.Writer, label, value string) {
	const indent = "    "
	prefix := indent + label + ": "
	if label == "-" {
		prefix = "  - "
	}
	continuation := strings.Repeat(" ", utf8.RuneCountInString(prefix))
	lines := wrapText(safeDisplay(value), terminalWidth-utf8.RuneCountInString(prefix))
	if len(lines) == 0 {
		fmt.Fprintln(w, prefix)
		return
	}
	fmt.Fprintln(w, prefix+lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintln(w, continuation+line)
	}
}

func wrapText(value string, width int) []string {
	if width < 1 {
		width = 1
	}
	words := strings.Fields(value)
	if len(words) == 0 {
		return nil
	}
	var out []string
	current := ""
	for _, word := range words {
		for utf8.RuneCountInString(word) > width {
			if current != "" {
				out = append(out, current)
				current = ""
			}
			runes := []rune(word)
			out = append(out, string(runes[:width]))
			word = string(runes[width:])
		}
		if current == "" {
			current = word
		} else if utf8.RuneCountInString(current)+1+utf8.RuneCountInString(word) <= width {
			current += " " + word
		} else {
			out = append(out, current)
			current = word
		}
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func MarkdownText(value string) string {
	return strings.NewReplacer("\\", "\\\\", "|", "\\|", "`", "\\`").Replace(safeDisplay(value))
}

// DisplayText strips control characters from untrusted text before terminal output.
func DisplayText(value string) string { return safeDisplay(value) }

func boundedDisplay(value string, maximum int) string {
	value = safeDisplay(value)
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	if maximum <= 1 {
		return string(runes[:maximum])
	}
	return string(runes[:maximum-1]) + "…"
}

// safeDisplay strips terminal/format controls from attacker-controlled names,
// paths, evidence, and provider text before they reach a human-facing renderer.
func safeDisplay(value string) string {
	var out strings.Builder
	for _, character := range value {
		if character == '\n' || character == '\r' || character == '\t' {
			out.WriteRune(' ')
			continue
		}
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			out.WriteRune('\uFFFD')
			continue
		}
		out.WriteRune(character)
	}
	return out.String()
}

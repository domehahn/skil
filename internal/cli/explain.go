package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// explanation is a stable, operator-facing projection of ScanResult. It is
// deliberately additive: ScanResult remains the canonical evidence contract.
type explanation struct {
	SchemaVersion string                `json:"schema_version"`
	Artifact      skil.Artifact         `json:"artifact"`
	Status        skil.Status           `json:"status"`
	Verdict       skil.Verdict          `json:"verdict"`
	Authoritative bool                  `json:"authoritative"`
	Summary       string                `json:"summary"`
	Issues        []explanationIssue    `json:"issues"`
	Coverage      []coverageExplanation `json:"coverage"`
	NextActions   []string              `json:"next_actions"`
}

type explanationIssue struct {
	Kind        string        `json:"kind"`
	Severity    skil.Severity `json:"severity,omitempty"`
	RuleID      string        `json:"rule_id,omitempty"`
	Title       string        `json:"title"`
	Location    skil.Location `json:"location,omitempty"`
	Explanation string        `json:"explanation"`
}

type coverageExplanation struct {
	Name  string             `json:"name"`
	State skil.CoverageState `json:"state"`
}

func (a *App) explain(ctx context.Context, args []string) int {
	_ = ctx
	fs := newFlags("explain", a.Err)
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "output file")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if fs.NArg() != 1 {
		return a.inputError(errors.New("explain requires a scan result JSON file"))
	}
	if *format != "terminal" && *format != "json" {
		return a.inputError(errors.New("explain supports terminal or json output"))
	}
	var scan skil.ScanResult
	if err := readStructured(fs.Arg(0), &scan); err != nil {
		return a.inputError(err)
	}
	if scan.SchemaVersion == "" || scan.Artifact.Digest == "" {
		return a.inputError(errors.New("scan result is missing schema_version or artifact.digest"))
	}
	result := buildExplanation(scan)
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if *format == "json" {
		if err := writeJSON(writer, result); err != nil {
			return a.internalError(err)
		}
	} else if err := writeExplanationTerminal(writer, result); err != nil {
		return a.internalError(err)
	}
	if scan.Status == skil.StatusFail {
		return ExitGateFail
	}
	return ExitOK
}

func buildExplanation(scan skil.ScanResult) explanation {
	result := explanation{
		SchemaVersion: "1.0.0",
		Artifact:      scan.Artifact,
		Status:        scan.Status,
		Verdict:       scan.Verdict,
		Authoritative: scan.Status != skil.StatusError && len(scan.Budget.Exceeded) == 0 && scan.Completeness.Failed == 0,
		Issues:        []explanationIssue{}, Coverage: []coverageExplanation{}, NextActions: []string{},
	}
	if scan.Status == skil.StatusPass && scan.Verdict == skil.VerdictClear {
		result.Summary = "The scan completed without an active blocking finding."
	} else if scan.Status == skil.StatusFail || scan.Verdict == skil.VerdictBlock {
		result.Summary = "The scan identified a blocking security or policy condition."
	} else {
		result.Summary = "The result requires review because the evidence is incomplete or non-final."
	}
	for _, finding := range activeFindings(scan.Findings) {
		result.Issues = append(result.Issues, explanationIssue{
			Kind: "finding", Severity: finding.Severity, RuleID: finding.RuleID,
			Title: finding.Title, Location: finding.Location,
			Explanation: firstNonEmptyCLI(finding.Remediation, finding.Description, finding.Message),
		})
	}
	for _, name := range sortedCoverageCLI(scan.Coverage) {
		state := scan.Coverage[name]
		result.Coverage = append(result.Coverage, coverageExplanation{Name: name, State: state})
		if state != skil.CoverageCompleted {
			result.Authoritative = false
			result.NextActions = append(result.NextActions, fmt.Sprintf("complete analysis %q (current state: %s)", name, state))
		}
	}
	if scan.Completeness.Failed > 0 || scan.Completeness.Completed < scan.Completeness.Applicable {
		result.Authoritative = false
		result.Issues = append(result.Issues, explanationIssue{Kind: "completeness", Title: "Inspection is incomplete", Explanation: fmt.Sprintf("%d of %d applicable work items completed", scan.Completeness.Completed, scan.Completeness.Applicable)})
		result.NextActions = append(result.NextActions, "rerun with the required analyzers available and inspect the completeness ledger")
	}
	if len(scan.Budget.Exceeded) > 0 {
		result.Authoritative = false
		result.Issues = append(result.Issues, explanationIssue{Kind: "budget", Title: "Analysis budget was exceeded", Explanation: strings.Join(scan.Budget.Exceeded, ", ")})
		result.NextActions = append(result.NextActions, "increase the analysis budget or reduce the artifact scope")
	}
	if scan.Closure != nil && scan.Closure.State != skil.AssuranceSafe {
		result.Authoritative = false
		result.Issues = append(result.Issues, explanationIssue{Kind: "closure", Title: "Assurance closure is not safe", Explanation: fmt.Sprintf("closure state is %s with %d unresolved required nodes", scan.Closure.State, scan.Closure.UnresolvedNodes)})
		result.NextActions = append(result.NextActions, "resolve, analyze, and verify all required closure members")
	}
	if scan.Analyzable.Opaque > 0 {
		result.Authoritative = false
		result.Issues = append(result.Issues, explanationIssue{Kind: "analyzability", Title: "Some content was opaque to analysis", Explanation: fmt.Sprintf("%d of %d files were opaque", scan.Analyzable.Opaque, scan.Analyzable.Files)})
		result.NextActions = append(result.NextActions, "inspect opaque executable or binary content before trusting the result")
	}
	if len(result.NextActions) == 0 && result.Authoritative {
		result.NextActions = append(result.NextActions, "retain the artifact digest and evidence bundle for later verification")
	}
	return result
}

func writeExplanationTerminal(w interface{ Write([]byte) (int, error) }, result explanation) error {
	fmt.Fprintf(w, "SKIL EXPLANATION\n\nArtifact: %s\nDigest:   sha256:%s\nStatus:   %s\nVerdict:  %s\nAuthoritative: %t\n\n%s\n", safeExplanationDisplay(result.Artifact.Name), result.Artifact.Digest, result.Status, result.Verdict, result.Authoritative, result.Summary)
	fmt.Fprintf(w, "\nISSUES (%d)\n", len(result.Issues))
	if len(result.Issues) == 0 {
		fmt.Fprintln(w, "- none")
	}
	for _, issue := range result.Issues {
		location := ""
		if issue.Location.File != "" {
			location = fmt.Sprintf(" (%s:%d)", safeExplanationDisplay(issue.Location.File), issue.Location.StartLine)
		}
		severity := ""
		if issue.Severity != "" {
			severity = string(issue.Severity) + " "
		}
		identifier := issue.Kind
		if issue.RuleID != "" {
			identifier += "/" + issue.RuleID
		}
		fmt.Fprintf(w, "- %s%s%s: %s\n", severity, identifier, location, safeExplanationDisplay(firstNonEmptyCLI(issue.Title, issue.Explanation)))
	}
	fmt.Fprintln(w, "\nNEXT ACTIONS")
	for _, action := range result.NextActions {
		fmt.Fprintf(w, "- %s\n", safeExplanationDisplay(action))
	}
	return nil
}

func sortedCoverageCLI(values map[string]skil.CoverageState) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func firstNonEmptyCLI(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "no additional detail"
}

func safeExplanationDisplay(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
}

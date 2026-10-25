package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	control "github.com/domehahn/skil/internal/continuous"
	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/pkg/skil"
)

type continuousReport struct {
	SchemaVersion string        `json:"schema_version"`
	State         control.State `json:"state"`
	ScanStatus    skil.Status   `json:"scan_status"`
	ScanVerdict   skil.Verdict  `json:"scan_verdict"`
	Policy        policy.Result `json:"policy"`
}

func (a *App) continuous(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(a.Err, "usage: skil continuous check <skill> --policy file --state file [--format terminal|json]")
		return ExitInput
	}
	fs := newFlags("continuous check", a.Err)
	policyPath := fs.String("policy", "", "policy file")
	statePath := fs.String("state", "", "persistent assurance state JSON")
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "report output file")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}
	if *policyPath == "" || *statePath == "" {
		return a.inputError(errors.New("--policy and --state are required"))
	}
	if *format != "terminal" && *format != "json" {
		return a.inputError(errors.New("continuous check supports terminal or json output"))
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		return a.inputError(err)
	}
	scan, contract, err := a.performScanConfigured(ctx, fs.Arg(0), "", analysis)
	if err != nil {
		return a.inputError(err)
	}
	decision := policy.Check(p, policy.Input{Scan: scan, Contract: contract})
	var previous *control.State
	if loaded, loadErr := control.Load(*statePath); loadErr == nil {
		previous = &loaded
	} else if !os.IsNotExist(loadErr) {
		return a.inputError(loadErr)
	}
	state := control.Evaluate(previous, fs.Arg(0), scan, decision, nowUTC())
	if err := control.Save(*statePath, state); err != nil {
		return a.internalError(err)
	}
	report := continuousReport{SchemaVersion: control.SchemaVersion, State: state, ScanStatus: scan.Status, ScanVerdict: scan.Verdict, Policy: decision}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if *format == "json" {
		if err := writeJSON(writer, report); err != nil {
			return a.internalError(err)
		}
	} else {
		fmt.Fprintf(writer, "Continuous assurance: %s\nArtifact: %s\nChanged: %t\nRuntime pin valid: %t\nAttestation refresh required: %t\nPolicy: %s\n", scan.Verdict, scan.Artifact.Name, state.Changed, state.RuntimePinValid, state.AttestationRefreshRequired, decision.Decision)
		for _, violation := range decision.Violations {
			fmt.Fprintf(writer, "- %s: %s\n", violation.Rule, violation.Message)
		}
	}
	if scan.Status == skil.StatusFail || decision.Decision == "DENY" {
		return ExitGateFail
	}
	return ExitOK
}

var nowUTC = func() time.Time { return time.Now().UTC() }

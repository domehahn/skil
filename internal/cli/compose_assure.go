package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/collection"
	"github.com/domehahn/skil/internal/compose"
	"github.com/domehahn/skil/internal/composeassure"
	"github.com/domehahn/skil/pkg/skil"
)

// composeAssure verifies skil compose's static cross-skill toxic-flow
// prediction against real observed runtime behavior: every skill in the
// collection that has its own eval.yaml runs its behavioral eval once
// each against one shared scratch workspace (unlike skil assure/eval,
// which each get their own fresh workspace) — so a real write from one
// skill and a real read from another can land on the same physical path
// — and the resulting operation traces are correlated into observed
// cross-skill flows, then reconciled against internal/compose.Analyze's
// static prediction. See internal/composeassure's package doc for exactly
// what "confirmed"/"static-only"/"runtime-only gap" mean.
func (a *App) composeAssure(ctx context.Context, args []string) int {
	fs := newFlags("compose assure", a.Err)
	runtimeCommand := fs.String("runtime-command", "", "executable for the isolated agent adapter, run once per skill that has its own eval")
	runtimeArgs := fs.String("runtime-args", "", "comma-separated isolated adapter arguments")
	maxOutput := fs.Int64("max-output-bytes", 1<<20, "maximum runtime stdout bytes per skill")
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "result output")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *analysis.listDomains {
		for _, d := range analyzer.DefaultRegistry(nil).Domains() {
			fmt.Fprintln(a.Out, d)
		}
		return ExitOK
	}
	if strings.TrimSpace(*runtimeCommand) == "" {
		return a.inputError(errors.New("compose assure requires --runtime-command for a real isolated agent adapter"))
	}
	if *format != "terminal" && *format != "json" {
		return a.inputError(errors.New("compose assure supports terminal or json output"))
	}
	collectionSource, cleanup, err := stageRemoteSource(ctx, fs.Arg(0), analysis.allowRemote != nil && *analysis.allowRemote)
	if err != nil {
		return a.inputError(err)
	}
	defer cleanup()
	roots, err := collection.Discover(collectionSource)
	if err != nil {
		return a.inputError(err)
	}
	if len(roots) < 2 {
		return a.inputError(fmt.Errorf("compose assure requires at least two skills in the collection; found %d", len(roots)))
	}

	scans := make([]skil.ScanResult, len(roots))
	for i, root := range roots {
		scan, _, err := a.performScanConfigured(ctx, root, "", analysis)
		if err != nil {
			return a.inputError(fmt.Errorf("scan %s: %w", root, err))
		}
		scans[i] = scan
	}
	staticResult := compose.Analyze(fs.Arg(0), scans)

	// One shared workspace across every skill's eval run in this
	// collection — the whole point: a physical resource one skill writes
	// must be the same physical resource another skill can actually read.
	workspace, err := os.MkdirTemp("", "skil-compose-assure-workspace-")
	if err != nil {
		return a.internalError(err)
	}
	defer os.RemoveAll(workspace)

	runs := make([]composeassure.SkillRun, len(roots))
	for i, scan := range scans {
		run := composeassure.SkillRun{Skill: scan.Artifact.Name, Path: roots[i]}
		evalPath := discoverEval(scan.Artifact)
		if evalPath == "" {
			run.Error = "no eval file found for this skill; skipped"
			runs[i] = run
			continue
		}
		run.EvalPath = evalPath
		evalResult, err := a.performEvaluationArtifact(ctx, scan.Artifact, evaluationOptions{
			RuntimeName: "isolated", RuntimeCommand: *runtimeCommand, RuntimeArgs: *runtimeArgs,
			MaxOutput: *maxOutput, Runs: 1, Workspace: workspace,
		})
		if err != nil {
			run.Error = err.Error()
			runs[i] = run
			continue
		}
		run.Evaluated = true
		for _, evalRun := range evalResult.Runs {
			run.Operations = append(run.Operations, evalRun.Trace.Operations...)
		}
		runs[i] = run
	}

	result := composeassure.Reconcile(staticResult, runs)

	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if *format == "json" {
		if err := writeJSON(writer, result); err != nil {
			return a.internalError(err)
		}
	} else {
		writeComposeAssureTerminal(writer, result)
	}
	if len(result.Confirmed) > 0 || len(result.RuntimeOnlyGaps) > 0 {
		return ExitGateFail
	}
	return ExitOK
}

func writeComposeAssureTerminal(writer interface{ Write([]byte) (int, error) }, result composeassure.Result) {
	fmt.Fprintf(writer, "MULTI-SKILL RUNTIME ASSURANCE\n\nSource: %s\nSkills: %d\n", result.Static.Source, len(result.Static.Skills))
	fmt.Fprintln(writer, "\nSkill runs")
	for _, run := range result.Runs {
		status := "evaluated"
		if !run.Evaluated {
			status = "not evaluated"
			if run.Error != "" {
				status += ": " + run.Error
			}
		}
		fmt.Fprintf(writer, "  - %-30s %s\n", run.Skill, status)
	}
	fmt.Fprintf(writer, "\nRuntime-confirmed toxic flows (%d)\n", len(result.Confirmed))
	for _, finding := range result.Confirmed {
		fmt.Fprintf(writer, "  - [%s] %s -> %s via %s\n", finding.RuleID, finding.Skills[0], finding.Skills[1], finding.Resource)
	}
	fmt.Fprintf(writer, "\nStatic-only findings, not observed this run (%d)\n", len(result.StaticOnly))
	for _, finding := range result.StaticOnly {
		fmt.Fprintf(writer, "  - [%s] %s -> %s via %s (not exercised by this eval run)\n", finding.RuleID, finding.Skills[0], finding.Skills[1], finding.Resource)
	}
	fmt.Fprintf(writer, "\nRuntime-only gaps: observed but not statically predicted (%d)\n", len(result.RuntimeOnlyGaps))
	for _, flow := range result.RuntimeOnlyGaps {
		fmt.Fprintf(writer, "  - %s -> %s via %s (correlation %s) — the static model missed this\n",
			flow.WriterSkill, flow.ReaderSkill, flow.Resource, flow.CorrelationID)
	}
}

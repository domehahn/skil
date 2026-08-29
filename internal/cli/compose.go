package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/collection"
	"github.com/domehahn/skil/internal/compose"
	"github.com/domehahn/skil/pkg/skil"
)

// compose scans every skill in a collection (the same discovery
// collection.Discover uses for scan-all) and then runs compose.Analyze
// across all of their results together, looking for capability
// combinations that only matter in composition — see internal/compose's
// package doc. Each skill is still scanned individually with the same
// analysis flags scan-all accepts; composition happens as an additional
// pass over the resulting CapabilityObservations, not instead of the
// normal per-skill scan.
func (a *App) compose(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "taint" {
		return a.composeTaint(ctx, args[1:])
	}
	fs := newFlags("compose", a.Err)
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "output file")
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
	if *format != "terminal" && *format != "json" {
		return a.inputError(errors.New("compose supports terminal or json output"))
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
		return a.inputError(errors.New("compose requires at least two skills in the collection; found " + fmt.Sprint(len(roots))))
	}
	scans := make([]skil.ScanResult, len(roots))
	for i, root := range roots {
		scan, _, err := a.performScanConfigured(ctx, root, "", analysis)
		if err != nil {
			return a.inputError(fmt.Errorf("scan %s: %w", root, err))
		}
		if collectionSource != fs.Arg(0) {
			scan.Artifact.Source = fs.Arg(0)
		}
		scans[i] = scan
	}
	result := compose.Analyze(fs.Arg(0), scans)

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
		fmt.Fprintf(writer, "skil cross-skill composition report\n\nSource: %s\nSkills: %d\nComposite findings: %d\n",
			result.Source, len(result.Skills), len(result.Findings))
		if len(result.Findings) == 0 {
			fmt.Fprintln(writer, "\nNo cross-skill composite risks detected.")
		}
		for i, finding := range result.Findings {
			fmt.Fprintf(writer, "\n%d. [%s] %s\n", i+1, finding.Severity, finding.Title)
			fmt.Fprintf(writer, "   Rule:     %s\n", finding.RuleID)
			fmt.Fprintf(writer, "   Skills:   %s -> %s\n", finding.Skills[0], finding.Skills[1])
			fmt.Fprintf(writer, "   Resource: %s\n", finding.Resource)
			fmt.Fprintf(writer, "   %s\n", finding.Message)
		}
	}
	if len(result.Findings) > 0 {
		return ExitGateFail
	}
	return ExitOK
}

func (a *App) composeTaint(ctx context.Context, args []string) int {
	fs := newFlags("compose taint", a.Err)
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "output file")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
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
		return a.inputError(errors.New("compose taint requires at least two skills in the collection; found " + fmt.Sprint(len(roots))))
	}
	scans := make([]skil.ScanResult, len(roots))
	for i, root := range roots {
		scan, _, err := a.performScanConfigured(ctx, root, "", analysis)
		if err != nil {
			return a.inputError(fmt.Errorf("scan %s: %w", root, err))
		}
		scans[i] = scan
	}
	result := compose.AnalyzeTaintFlows(fs.Arg(0), scans)

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
		fmt.Fprintf(writer, "SKIL CROSS-SKILL TAINT PIPELINE REPORT\n\nSource: %s\nSkills: %d\nTaint Chains: %d\n",
			result.Source, len(result.Skills), len(result.TaintChains))
		if len(result.TaintChains) == 0 {
			fmt.Fprintln(writer, "\nNo cross-skill taint flow pipelines detected.")
		}
		for i, chain := range result.TaintChains {
			fmt.Fprintf(writer, "\n%d. [%s] %s\n", i+1, chain.Severity, chain.Title)
			fmt.Fprintf(writer, "   Rule:    %s\n", chain.RuleID)
			fmt.Fprintf(writer, "   Path:    %s\n", strings.Join(chain.TaintPath, " -> "))
			fmt.Fprintf(writer, "   Source:  %s (%s)\n", chain.SourceSkill, chain.SourceType)
			fmt.Fprintf(writer, "   Sink:    %s (%s)\n", chain.SinkSkill, chain.SinkType)
			fmt.Fprintf(writer, "   %s\n", chain.Message)
		}
	}
	if len(result.TaintChains) > 0 {
		return ExitGateFail
	}
	return ExitOK
}

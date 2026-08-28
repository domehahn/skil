package cli

import (
	"fmt"

	"github.com/domehahn/skil/internal/remediation"
)

func (a *App) fix(args []string) int {
	fs := newFlags("fix", a.Err)
	workspace := fs.String("workspace", ".", "workspace directory to remediate")
	dryRun := fs.Bool("dry-run", false, "perform dry run without writing changes to disk")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	result, err := remediation.FixWorkspace(*workspace, *dryRun)
	if err != nil {
		return a.inputError(fmt.Errorf("fix workspace: %w", err))
	}

	if *dryRun {
		fmt.Fprintln(a.Out, "[DRY-RUN] Remediations required:")
	} else {
		fmt.Fprintln(a.Out, "Remediations applied successfully:")
	}

	for _, action := range result.ActionsTaken {
		fmt.Fprintf(a.Out, "  - %s\n", action)
	}

	if len(result.ActionsTaken) == 0 {
		fmt.Fprintln(a.Out, "No remediations required; workspace is clean.")
	}

	return ExitOK
}

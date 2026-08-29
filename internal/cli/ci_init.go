package cli

import (
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/ci"
)

func (a *App) ci(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("ci requires a subcommand, e.g. skil ci init"))
	}

	switch args[0] {
	case "init":
		return a.ciInit(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown ci subcommand %q", args[0]))
	}
}

func (a *App) ciInit(args []string) int {
	fs := newFlags("ci init", a.Err)
	workspace := fs.String("workspace", ".", "workspace root directory")
	platform := fs.String("platform", "github", "CI platform: github or gitlab")
	policyPath := fs.String("policy", ".skil/policy.yaml", "policy file to bind in CI pipeline")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	targetFile, err := ci.InitCI(*workspace, *platform, *policyPath)
	if err != nil {
		return a.inputError(err)
	}

	fmt.Fprintf(a.Out, "Successfully generated %s CI workflow file: %s\n", *platform, targetFile)
	return ExitOK
}

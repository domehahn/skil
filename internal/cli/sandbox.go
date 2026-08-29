package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/sandbox"
)

func (a *App) sandbox(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("sandbox requires a subcommand: run"))
	}

	switch args[0] {
	case "run":
		return a.sandboxRun(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown sandbox subcommand %q", args[0]))
	}
}

func (a *App) sandboxRun(args []string) int {
	fs := newFlags("sandbox run", a.Err)
	workspace := fs.String("workspace", ".", "workspace root directory")
	format := fs.String("format", "terminal", "terminal or json")

	if err := fs.Parse(interspersed(fs, args)); err != nil || fs.NArg() < 1 {
		fs.Usage()
		return ExitInput
	}

	cmdArgs := fs.Args()
	res, err := sandbox.RunSandboxed(cmdArgs, sandbox.SandboxOptions{
		WorkspaceRoot: *workspace,
	})
	if err != nil {
		return a.inputError(err)
	}

	if *format == "json" {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(a.Out, string(data))
		return ExitOK
	}

	fmt.Fprint(a.Out, res.Stdout)
	if res.Stderr != "" {
		fmt.Fprint(a.Err, res.Stderr)
	}

	if res.ExitCode != 0 {
		return ExitGateFail
	}
	return ExitOK
}

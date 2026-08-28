package cli

import (
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/githook"
)

func (a *App) hook(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("hook requires a subcommand: install or uninstall"))
	}

	switch args[0] {
	case "install":
		return a.hookInstall(args[1:])
	case "uninstall":
		return a.hookUninstall(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown hook subcommand %q", args[0]))
	}
}

func (a *App) hookInstall(args []string) int {
	fs := newFlags("hook install", a.Err)
	workspace := fs.String("workspace", ".", "workspace root directory")
	strict := fs.Bool("strict", false, "enable strict pre-commit enforcement")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	if err := githook.InstallHook(*workspace, *strict); err != nil {
		return a.inputError(err)
	}

	fmt.Fprintf(a.Out, "Successfully installed SKIL Git pre-commit hook in %s/.git/hooks/pre-commit\n", *workspace)
	return ExitOK
}

func (a *App) hookUninstall(args []string) int {
	fs := newFlags("hook uninstall", a.Err)
	workspace := fs.String("workspace", ".", "workspace root directory")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	if err := githook.UninstallHook(*workspace); err != nil {
		return a.inputError(err)
	}

	fmt.Fprintf(a.Out, "Successfully uninstalled SKIL Git pre-commit hook from %s/.git/hooks/pre-commit\n", *workspace)
	return ExitOK
}

package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/mesh"
)

func (a *App) mesh(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("mesh requires a subcommand: verify"))
	}

	switch args[0] {
	case "verify":
		return a.meshVerify(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown mesh subcommand %q", args[0]))
	}
}

func (a *App) meshVerify(args []string) int {
	fs := newFlags("mesh verify", a.Err)
	workspace := fs.String("workspace", ".", "workspace root directory")
	format := fs.String("format", "terminal", "terminal or json")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	proof, err := mesh.VerifyMesh(*workspace)
	if err != nil {
		return a.inputError(err)
	}

	if *format == "json" {
		data, _ := json.MarshalIndent(proof, "", "  ")
		fmt.Fprintln(a.Out, string(data))
		return ExitOK
	}

	if proof.IsMonotonic {
		fmt.Fprintf(a.Out, "[skil] MULTI-AGENT MESH PROOF PASSED for workspace %q: Monotonic least-privilege delegation verified.\n", proof.WorkspaceRoot)
		return ExitOK
	}

	fmt.Fprintf(a.Err, "[skil] MULTI-AGENT MESH PROOF FAILED for workspace %q: Violations: %v\n", proof.WorkspaceRoot, proof.Violations)
	return ExitGateFail
}

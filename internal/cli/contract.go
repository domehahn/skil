package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/contracts"
)

func (a *App) contract(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("contract requires a subcommand: verify"))
	}

	switch args[0] {
	case "verify":
		return a.contractVerify(ctx, args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown contract subcommand %q", args[0]))
	}
}

func (a *App) contractVerify(ctx context.Context, args []string) int {
	fs := newFlags("contract verify", a.Err)
	format := fs.String("format", "terminal", "terminal or json")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	skillPath := fs.Arg(0)
	proof, err := contracts.VerifyFormalContract(ctx, skillPath)
	if err != nil {
		return a.inputError(err)
	}

	if *format == "json" {
		data, _ := json.MarshalIndent(proof, "", "  ")
		fmt.Fprintln(a.Out, string(data))
		return ExitOK
	}

	if proof.IsProved {
		fmt.Fprintf(a.Out, "[skil] FORMAL PROOF PASSED for skill %q: No unbounded high-risk capabilities detected.\n", proof.SkillName)
		return ExitOK
	}

	fmt.Fprintf(a.Err, "[skil] FORMAL PROOF FAILED for skill %q: Unbounded capabilities: %v\n", proof.SkillName, proof.UnboundedCapabilities)
	return ExitGateFail
}

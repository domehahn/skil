package cli

import (
	"fmt"

	"github.com/domehahn/skil/internal/policy"
)

func (a *App) policyAdapt(args []string) int {
	fs := newFlags("policy adapt", a.Err)
	trace := fs.String("trace", "", "execution trace log JSON path")
	output := fs.String("output", ".skil/policy.yaml", "output policy YAML path")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	if *trace == "" {
		return a.inputError(fmt.Errorf("policy adapt requires --trace <trace.json>"))
	}

	_, yamlStr, err := policy.AdaptPolicyFromTrace(*trace, *output)
	if err != nil {
		return a.inputError(err)
	}

	fmt.Fprintf(a.Out, "Successfully adapted self-tightening policy to %s:\n%s\n", *output, yamlStr)
	return ExitOK
}

package cli

import (
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/gate"
)

func (a *App) gate(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("gate requires a subcommand, e.g. skil gate check"))
	}

	switch args[0] {
	case "check":
		return a.gateCheck(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown gate subcommand %q", args[0]))
	}
}

func (a *App) gateCheck(args []string) int {
	fs := newFlags("gate check", a.Err)
	artifactPath := fs.String("artifact", "", "artifact directory or package blob to verify")
	attestationPath := fs.String("attestation", "", "attestation JSON file to verify")
	policyPath := fs.String("policy", "", "policy YAML file to enforce")
	format := fs.String("format", "terminal", "terminal or json")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	if *artifactPath == "" || *attestationPath == "" {
		return a.inputError(errors.New("--artifact and --attestation parameters are required for gate check"))
	}

	result, err := gate.CheckGate(gate.GateOptions{
		ArtifactPath:    *artifactPath,
		AttestationPath: *attestationPath,
		PolicyPath:      *policyPath,
	})

	if err != nil {
		return a.inputError(err)
	}

	if *format == "json" {
		if err := writeJSON(a.Out, result); err != nil {
			return a.internalError(err)
		}
	} else {
		if result.Allowed {
			fmt.Fprintf(a.Out, "ADMISSION APPROVED: %s\n", result.Reason)
			fmt.Fprintf(a.Out, "  Artifact SHA256:    %s\n", result.ArtifactDigest)
			fmt.Fprintf(a.Out, "  Attestation Subject: %s\n", result.AttestationSubject)
			if result.ClosureDigest != "" {
				fmt.Fprintf(a.Out, "  Closure SHA256:     %s\n", result.ClosureDigest)
			}
		} else {
			fmt.Fprintf(a.Err, "ADMISSION DENIED: %s\n", result.Reason)
			for _, v := range result.Violations {
				fmt.Fprintf(a.Err, "  - Violation [%s]: %s\n", v.Rule, v.Message)
			}
		}
	}

	if !result.Allowed {
		return ExitGateFail
	}

	return ExitOK
}

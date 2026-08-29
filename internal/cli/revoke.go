package cli

import (
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/revocation"
)

func (a *App) revoke(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("revoke requires a subcommand: add, check, or list"))
	}

	switch args[0] {
	case "add":
		return a.revokeAdd(args[1:])
	case "check":
		return a.revokeCheck(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown revoke subcommand %q", args[0]))
	}
}

func (a *App) revokeAdd(args []string) int {
	fs := newFlags("revoke add", a.Err)
	regPath := fs.String("registry", ".skil/revocations.json", "revocation registry path")
	reason := fs.String("reason", "Revoked by security operator", "revocation reason")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	digest := fs.Arg(0)
	if err := revocation.RevokeDigest(*regPath, digest, *reason); err != nil {
		return a.inputError(err)
	}

	fmt.Fprintf(a.Out, "Successfully revoked attestation digest %q in %s\n", digest, *regPath)
	return ExitOK
}

func (a *App) revokeCheck(args []string) int {
	fs := newFlags("revoke check", a.Err)
	regPath := fs.String("registry", ".skil/revocations.json", "revocation registry path")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	digest := fs.Arg(0)
	revoked, reason, err := revocation.IsRevoked(*regPath, digest)
	if err != nil {
		return a.inputError(err)
	}

	if revoked {
		fmt.Fprintf(a.Err, "[skil] REVOKED: Attestation digest %q was revoked! Reason: %s\n", digest, reason)
		return ExitGateFail
	}

	fmt.Fprintf(a.Out, "[skil] VALID: Attestation digest %q is active and not revoked.\n", digest)
	return ExitOK
}

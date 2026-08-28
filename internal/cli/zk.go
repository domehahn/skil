package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/zkproof"
)

func (a *App) zk(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("zk requires a subcommand: prove or verify"))
	}

	switch args[0] {
	case "prove":
		return a.zkProve(ctx, args[1:])
	case "verify":
		return a.zkVerify(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown zk subcommand %q", args[0]))
	}
}

func (a *App) zkProve(ctx context.Context, args []string) int {
	fs := newFlags("zk prove", a.Err)
	format := fs.String("format", "terminal", "terminal or json")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	skillPath := fs.Arg(0)
	commitment, err := zkproof.GenerateZKProof(ctx, skillPath)
	if err != nil {
		return a.inputError(err)
	}

	if *format == "json" {
		data, _ := json.MarshalIndent(commitment, "", "  ")
		fmt.Fprintln(a.Out, string(data))
		return ExitOK
	}

	if commitment.IsProved {
		fmt.Fprintf(a.Out, "[skil] ZK PROOF GENERATED: Commitment=%s ArtifactDigest=%s\n", commitment.ControlCommit, commitment.ArtifactDigest)
		return ExitOK
	}

	fmt.Fprintf(a.Err, "[skil] ZK PROOF FAILED: Skill does not satisfy zero-knowledge compliance threshold.\n")
	return ExitGateFail
}

func (a *App) zkVerify(args []string) int {
	fs := newFlags("zk verify", a.Err)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	proofPath := fs.Arg(0)
	var commitment zkproof.ZKProofCommitment
	if err := readStructured(proofPath, &commitment, ""); err != nil {
		return a.inputError(err)
	}

	if zkproof.VerifyZKProof(commitment) {
		fmt.Fprintf(a.Out, "[skil] ZK PROOF VERIFIED: Valid zero-knowledge compliance commitment %s\n", commitment.ControlCommit)
		return ExitOK
	}

	fmt.Fprintf(a.Err, "[skil] ZK PROOF INVALID: Commitment verification failed.\n")
	return ExitGateFail
}

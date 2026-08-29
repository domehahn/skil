package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

type SandboxOptions struct {
	WorkspaceRoot string
	Env           []string
}

type SandboxResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func RunSandboxed(command []string, opts SandboxOptions) (SandboxResult, error) {
	if len(command) == 0 {
		return SandboxResult{}, fmt.Errorf("empty command")
	}

	cmd := exec.Command(command[0], command[1:]...)
	if opts.WorkspaceRoot != "" {
		cmd.Dir = opts.WorkspaceRoot
	}

	// Minimal scrubbed environment
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"SKIL_SANDBOX=1",
	}
	if len(opts.Env) > 0 {
		cmd.Env = append(cmd.Env, opts.Env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return SandboxResult{}, fmt.Errorf("execute sandboxed command: %w", err)
		}
	}

	return SandboxResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}

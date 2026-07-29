package eval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type IsolationRequest struct {
	Executable  string
	Args        []string
	Environment []string
	Stdin       []byte
}

// IsolationProvider is a privileged trust boundary. Implementations must
// prevent direct network access and host writes. Authorized effects can happen
// only through a registered host GatewayTool after skil enforcer approval.
type IsolationProvider interface {
	ID() string
	Run(context.Context, IsolationRequest, io.Writer, io.Writer) error
}

type IsolationLimits struct {
	MemoryBytes int64
}

type ResourceIsolationProvider interface {
	IsolationProvider
	RunWithLimits(context.Context, IsolationRequest, IsolationLimits, io.Writer, io.Writer) error
}

type NativeIsolation struct {
	helper  string
	limiter string
	os      string
}

func NewNativeIsolation() (*NativeIsolation, error) {
	var helper string
	var err error
	switch runtime.GOOS {
	case "darwin":
		helper, err = exec.LookPath("sandbox-exec")
		if err == nil {
			probe := exec.Command(helper, "-p", "(version 1) (allow default)", "/usr/bin/true")
			if probe.Run() != nil {
				return nil, errors.New("native macOS isolation helper cannot apply a sandbox profile")
			}
		}
	case "linux":
		helper, err = exec.LookPath("bwrap")
	case "windows":
		err = windowsIsolationAvailable()
	default:
		return nil, fmt.Errorf("no built-in isolation provider for %s", runtime.GOOS)
	}
	if err != nil {
		return nil, errors.New("required native isolation helper is unavailable")
	}
	limiter := ""
	if runtime.GOOS == "linux" {
		limiter, _ = exec.LookPath("prlimit")
	}
	return &NativeIsolation{helper: helper, limiter: limiter, os: runtime.GOOS}, nil
}

func (n *NativeIsolation) ID() string { return "native-" + n.os }

func (n *NativeIsolation) Run(ctx context.Context, request IsolationRequest, stdout, stderr io.Writer) error {
	return n.run(ctx, request, IsolationLimits{}, stdout, stderr)
}

func (n *NativeIsolation) RunWithLimits(ctx context.Context, request IsolationRequest, limits IsolationLimits, stdout, stderr io.Writer) error {
	if limits.MemoryBytes <= 0 {
		return n.Run(ctx, request, stdout, stderr)
	}
	if n.os == "windows" {
		return n.run(ctx, request, limits, stdout, stderr)
	}
	if n.os != "linux" || n.limiter == "" {
		return errors.New("native isolation provider cannot enforce a hard memory limit")
	}
	return n.run(ctx, request, limits, stdout, stderr)
}

func (n *NativeIsolation) run(ctx context.Context, request IsolationRequest, limits IsolationLimits, stdout, stderr io.Writer) error {
	executable, err := exec.LookPath(request.Executable)
	if err != nil {
		return fmt.Errorf("resolve isolated executable: %w", err)
	}
	if !filepath.IsAbs(executable) {
		executable, err = filepath.Abs(executable)
		if err != nil {
			return fmt.Errorf("resolve isolated executable path: %w", err)
		}
	}
	if n.os == "darwin" {
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return fmt.Errorf("canonicalize isolated executable path: %w", err)
		}
	}
	scratch, err := os.MkdirTemp("", "skil-isolated-")
	if err != nil {
		return fmt.Errorf("create isolated scratch directory: %w", err)
	}
	defer os.RemoveAll(scratch)
	var command *exec.Cmd
	tmpDir := scratch
	switch n.os {
	case "darwin":
		tmpDir, err = filepath.EvalSymlinks(scratch)
		if err != nil {
			return fmt.Errorf("canonicalize isolated scratch directory: %w", err)
		}
		executableRoot := "/" + strings.Split(strings.TrimPrefix(executable, "/"), "/")[0]
		profile := `(version 1)
(deny default)
(allow process-fork)
(allow process-exec (literal ` + strconv.Quote(executable) + `))
(allow sysctl-read)
(allow file-read* (literal "/") (literal "/private") (literal "/System") (literal "/usr") (literal "/Library") (literal ` + strconv.Quote(executableRoot) + `) (literal ` + strconv.Quote(executable) + `) (subpath "/usr/lib") (subpath "/System/Library") (subpath "/System/Volumes/Preboot/Cryptexes/OS") (subpath "/Library/Apple"))
(allow file-write* (subpath ` + strconv.Quote(tmpDir) + `))
(deny network*)`
		args := append([]string{"-p", profile, "--", executable}, request.Args...)
		command = exec.CommandContext(ctx, n.helper, args...)
	case "linux":
		tmpDir = "/tmp"
		args := []string{"--die-with-parent", "--new-session", "--unshare-all",
			"--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
			"--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
			"--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
			"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
			"--ro-bind", executable, "/skil-adapter", "--chdir", "/tmp",
			"--", "/skil-adapter"}
		args = append(args, request.Args...)
		if limits.MemoryBytes > 0 {
			limitedArgs := []string{"--data=" + strconv.FormatInt(limits.MemoryBytes, 10), "--", n.helper}
			command = exec.CommandContext(ctx, n.limiter, append(limitedArgs, args...)...)
		} else {
			command = exec.CommandContext(ctx, n.helper, args...)
		}
	case "windows":
		return runWindowsIsolation(ctx, executable, request, limits, scratch, stdout, stderr)
	default:
		return errors.New("unsupported native isolation provider")
	}
	command.Env = append(append([]string(nil), request.Environment...), "TMPDIR="+tmpDir)
	command.Stdin = bytes.NewReader(request.Stdin)
	command.Stdout, command.Stderr = stdout, stderr
	return command.Run()
}

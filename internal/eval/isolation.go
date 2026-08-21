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
	"sync"
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

// Session is a live, sandboxed process with streaming stdio — for a
// protocol (e.g. MCP's JSON-RPC-over-stdio) that needs multiple
// request/response round-trips over one long-lived process, unlike
// IsolationProvider.Run's one-shot "fixed stdin in, captured stdout out,
// wait for exit" model. It carries exactly the same sandboxing guarantees
// (no direct network access, no host writes outside an isolated scratch
// area) as Run — Start below applies the identical per-OS sandbox
// arguments, just wired for streaming instead of batch I/O.
type Session interface {
	// Stdin is the sandboxed process's stdin.
	Stdin() io.WriteCloser
	// Stdout is the sandboxed process's stdout. Callers needing
	// line-delimited framing (e.g. JSON-RPC, one message per line)
	// should wrap it in a bufio.Scanner/Reader.
	Stdout() io.Reader
	// Wait blocks until the process exits on its own, or until ctx (the
	// context passed to Start) is done — in which case the process is
	// forcibly terminated and ctx.Err() is returned.
	Wait() error
	// Close forcibly terminates the process and releases every
	// resource. Safe to call multiple times, and safe to call whether
	// or not Wait has returned; a caller unsure whether the session is
	// still needed should always defer Close.
	Close() error
}

// StreamingIsolationProvider is the interactive counterpart to
// IsolationProvider for isolation backends that support it.
type StreamingIsolationProvider interface {
	IsolationProvider
	Start(ctx context.Context, request IsolationRequest) (Session, error)
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
	if n.os == "windows" {
		executable, scratch, err := n.resolveExecutable(request.Executable)
		if err != nil {
			return err
		}
		defer os.RemoveAll(scratch)
		return runWindowsIsolation(ctx, executable, request, limits, scratch, stdout, stderr)
	}
	command, cleanup, err := n.buildSandboxCommand(ctx, request, limits)
	if err != nil {
		return err
	}
	defer cleanup()
	command.Stdin = bytes.NewReader(request.Stdin)
	command.Stdout, command.Stderr = stdout, stderr
	return command.Run()
}

// resolveExecutable looks up request.Executable on PATH, makes it
// absolute, canonicalizes symlinks on darwin (sandbox-exec profiles name
// an exact literal path), and creates the isolated scratch directory
// every OS branch needs. Callers must remove the returned scratch
// directory when done.
func (n *NativeIsolation) resolveExecutable(name string) (executable, scratch string, err error) {
	executable, err = exec.LookPath(name)
	if err != nil {
		return "", "", fmt.Errorf("resolve isolated executable: %w", err)
	}
	if !filepath.IsAbs(executable) {
		executable, err = filepath.Abs(executable)
		if err != nil {
			return "", "", fmt.Errorf("resolve isolated executable path: %w", err)
		}
	}
	if n.os == "darwin" {
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return "", "", fmt.Errorf("canonicalize isolated executable path: %w", err)
		}
	}
	scratch, err = os.MkdirTemp("", "skil-isolated-")
	if err != nil {
		return "", "", fmt.Errorf("create isolated scratch directory: %w", err)
	}
	return executable, scratch, nil
}

// buildSandboxCommand constructs the sandboxed *exec.Cmd for darwin
// (sandbox-exec) or linux (bwrap[+prlimit]) — the exact same sandbox
// profile/arguments run() has always used, factored out so both the
// one-shot run() and the streaming Start() build an identical sandbox
// and only differ in how they wire stdio and drive the process. Not
// used for windows, whose process-creation model (AppContainer via raw
// CreateProcess) is not an exec.Cmd at all — see runWindowsIsolation /
// startWindowsIsolation. The returned cleanup func removes the scratch
// directory and must be called (typically deferred) once the command
// has been run or the session closed.
func (n *NativeIsolation) buildSandboxCommand(ctx context.Context, request IsolationRequest, limits IsolationLimits) (*exec.Cmd, func(), error) {
	executable, scratch, err := n.resolveExecutable(request.Executable)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(scratch) }
	var command *exec.Cmd
	tmpDir := scratch
	switch n.os {
	case "darwin":
		tmpDir, err = filepath.EvalSymlinks(scratch)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("canonicalize isolated scratch directory: %w", err)
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
	default:
		cleanup()
		return nil, nil, errors.New("unsupported native isolation provider")
	}
	command.Env = append(append([]string(nil), request.Environment...), "TMPDIR="+tmpDir)
	return command, cleanup, nil
}

// Start begins a streaming Session with the same sandbox every Run call
// uses. On windows it delegates to startWindowsIsolation, which reuses
// runWindowsIsolation's AppContainer/job setup verbatim and only differs
// in how the resulting process's stdio is handed to the caller.
func (n *NativeIsolation) Start(ctx context.Context, request IsolationRequest) (Session, error) {
	if n.os == "windows" {
		executable, scratch, err := n.resolveExecutable(request.Executable)
		if err != nil {
			return nil, err
		}
		session, err := startWindowsIsolation(ctx, executable, request, scratch)
		if err != nil {
			os.RemoveAll(scratch)
			return nil, err
		}
		return session, nil
	}
	command, cleanup, err := n.buildSandboxCommand(ctx, request, IsolationLimits{})
	if err != nil {
		return nil, err
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("open isolated stdin pipe: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("open isolated stdout pipe: %w", err)
	}
	// Stderr has no interactive consumer for a streaming session (unlike
	// Run, which hands the caller an io.Writer for it); discarding
	// rather than leaving it unset avoids a sandboxed process blocking
	// on a full pipe buffer if it writes a lot to stderr.
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		cleanup()
		return nil, fmt.Errorf("start isolated process: %w", err)
	}
	return &nativeSession{ctx: ctx, cmd: command, stdin: stdin, stdout: stdout, cleanup: cleanup}, nil
}

// nativeSession implements Session for the darwin/linux exec.Cmd-based
// sandbox. Close/Wait are safe to call any number of times and in any
// order — both funnel through a single sync.Once-guarded shutdown so a
// caller that defers Close after also calling Wait never double-closes
// pipes or double-kills an already-exited process.
type nativeSession struct {
	ctx     context.Context
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	cleanup func()
	once    sync.Once
	waitErr error
}

func (s *nativeSession) Stdin() io.WriteCloser { return s.stdin }
func (s *nativeSession) Stdout() io.Reader     { return s.stdout }

func (s *nativeSession) Wait() error {
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-s.ctx.Done():
		_ = s.cmd.Process.Kill()
		<-done
		_ = s.Close()
		return s.ctx.Err()
	case err := <-done:
		_ = s.Close()
		return err
	}
}

func (s *nativeSession) Close() error {
	s.once.Do(func() {
		_ = s.stdin.Close()
		_ = s.stdout.Close()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		s.cleanup()
	})
	return nil
}

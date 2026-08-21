package eval

import (
	"bufio"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestNativeIsolationStreamsInteractiveSession proves Start/Session drives a
// genuine multi-round-trip, bidirectional stdio conversation with a real
// sandboxed subprocess — not just a one-shot batch write/drain like
// Run/RunWithLimits. It reuses the same self-exec test-binary-as-adapter
// trick as TestNativeIsolationExecutesAdapterWhenAvailable (see
// TestIsolatedAdapterHelper's "stream-echo" branch), and is gated behind the
// same env var since it depends on the real native sandbox helper
// (sandbox-exec/bwrap/AppContainer) being available on the host.
func TestNativeIsolationStreamsInteractiveSession(t *testing.T) {
	if os.Getenv("SKIL_REQUIRE_NATIVE_ISOLATION") != "1" {
		t.Skip("native isolation integration test requires SKIL_REQUIRE_NATIVE_ISOLATION=1")
	}
	isolation, err := NewNativeIsolation()
	if err != nil {
		t.Fatalf("required native isolation unavailable: %v", err)
	}
	streaming, ok := any(isolation).(StreamingIsolationProvider)
	if !ok {
		t.Fatal("NativeIsolation does not implement StreamingIsolationProvider")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := streaming.Start(ctx, IsolationRequest{
		Executable: os.Args[0],
		Args:       []string{"-test.run=TestIsolatedAdapterHelper", "--", "stream-echo"},
	})
	if err != nil {
		t.Fatalf("start streaming session: %v", err)
	}
	defer session.Close()

	stdin := session.Stdin()
	reader := bufio.NewScanner(session.Stdout())

	// Multiple round-trips over the same live process: proves this is a
	// genuinely interactive session, not IsolationProvider.Run's fixed
	// stdin-in/stdout-out-at-exit model.
	for _, line := range []string{"first", "second", "third"} {
		if _, err := stdin.Write([]byte(line + "\n")); err != nil {
			t.Fatalf("write to sandboxed stdin: %v", err)
		}
		if !reader.Scan() {
			t.Fatalf("sandboxed process closed stdout early waiting for reply to %q: %v", line, reader.Err())
		}
		want := "echo: " + line
		if got := reader.Text(); got != want {
			t.Fatalf("round-trip mismatch: got %q, want %q", got, want)
		}
	}

	if err := stdin.Close(); err != nil {
		t.Fatalf("close sandboxed stdin: %v", err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("sandboxed process did not exit cleanly after stdin close: %v", err)
	}
}

// TestNativeIsolationSessionCancellationKillsProcess proves Wait respects
// context cancellation by forcibly terminating a process that would
// otherwise never exit on its own (the sandboxed "stream-echo" adapter
// blocks reading stdin forever until it's closed or killed).
func TestNativeIsolationSessionCancellationKillsProcess(t *testing.T) {
	if os.Getenv("SKIL_REQUIRE_NATIVE_ISOLATION") != "1" {
		t.Skip("native isolation integration test requires SKIL_REQUIRE_NATIVE_ISOLATION=1")
	}
	isolation, err := NewNativeIsolation()
	if err != nil {
		t.Fatalf("required native isolation unavailable: %v", err)
	}
	streaming, ok := any(isolation).(StreamingIsolationProvider)
	if !ok {
		t.Fatal("NativeIsolation does not implement StreamingIsolationProvider")
	}

	ctx, cancel := context.WithCancel(context.Background())
	session, err := streaming.Start(ctx, IsolationRequest{
		Executable: os.Args[0],
		Args:       []string{"-test.run=TestIsolatedAdapterHelper", "--", "stream-echo"},
	})
	if err != nil {
		cancel()
		t.Fatalf("start streaming session: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait after cancellation returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return within 5s of context cancellation; process was not killed")
	}
}

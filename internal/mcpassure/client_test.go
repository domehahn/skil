package mcpassure

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/eval"
)

// fakeSession is a real in-process, in-memory bidirectional pipe pair
// driven by a goroutine playing the MCP server — it exercises the actual
// JSON-RPC wire format and framing the real client speaks, without
// depending on a native OS sandbox (unlike internal/eval's own
// SKIL_REQUIRE_NATIVE_ISOLATION-gated integration tests), so these tests
// run unconditionally on every CI platform.
type fakeSession struct {
	clientWrite *io.PipeWriter // client (Discover) writes requests here
	serverRead  *io.PipeReader // server goroutine reads requests here
	serverWrite *io.PipeWriter // server goroutine writes responses here
	clientRead  *io.PipeReader // client (Discover) reads responses here
	closeOnce   sync.Once
}

func newFakeSession(serve func(requests <-chan string, respond func(line string))) *fakeSession {
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()
	session := &fakeSession{
		clientWrite: clientWrite, serverRead: serverRead,
		serverWrite: serverWrite, clientRead: clientRead,
	}
	requests := make(chan string, 16)
	go func() {
		defer close(requests)
		scanner := bufio.NewScanner(serverRead)
		scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for scanner.Scan() {
			requests <- scanner.Text()
		}
	}()
	respond := func(line string) {
		fmt.Fprintf(serverWrite, "%s\n", line)
	}
	go serve(requests, respond)
	return session
}

func (s *fakeSession) Stdin() io.WriteCloser { return s.clientWrite }
func (s *fakeSession) Stdout() io.Reader     { return s.clientRead }
func (s *fakeSession) Wait() error           { return nil }
func (s *fakeSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.clientWrite.Close()
		_ = s.serverRead.Close()
		_ = s.serverWrite.Close()
		_ = s.clientRead.Close()
	})
	return nil
}

// rpcID extracts the request "id" field, mirroring how a real server would
// echo it back on the response.
func rpcID(line string) json.RawMessage {
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal([]byte(line), &envelope)
	return envelope.ID
}

func rpcMethod(line string) string {
	var envelope struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal([]byte(line), &envelope)
	return envelope.Method
}

func wellBehavedServer(toolDescription string) func(<-chan string, func(string)) {
	return func(requests <-chan string, respond func(string)) {
		for line := range requests {
			switch rpcMethod(line) {
			case "initialize":
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"fake-mcp-server","version":"1.0.0"}}}`, string(rpcID(line))))
			case "notifications/initialized":
				// notification: no response
			case "tools/list":
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"read_file","description":%s}]}}`,
					string(rpcID(line)), mustJSON(toolDescription)))
			case "prompts/list":
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"prompts":[]}}`, string(rpcID(line))))
			case "resources/list":
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"resources":[]}}`, string(rpcID(line))))
			}
		}
	}
}

func mustJSON(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestDiscoverPerformsRealHandshakeAndParsesToolMetadata(t *testing.T) {
	session := newFakeSession(wellBehavedServer("Reads a file from the workspace."))
	defer session.Close()

	discovery, err := Discover(context.Background(), session, Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if discovery.ServerName != "fake-mcp-server" || discovery.ProtocolVersion != "2025-06-18" {
		t.Fatalf("unexpected server identity: %#v", discovery)
	}
	if len(discovery.Tools) != 1 || discovery.Tools[0].Name != "read_file" ||
		discovery.Tools[0].Description != "Reads a file from the workspace." {
		t.Fatalf("unexpected tools: %#v", discovery.Tools)
	}
}

// TestDiscoverToleratesMissingPromptsAndResources proves a server that
// doesn't implement prompts/list or resources/list (a real, common MCP
// server shape — these are optional capabilities) doesn't fail the whole
// handshake, per JSON-RPC's own method-not-found convention.
func TestDiscoverToleratesMissingPromptsAndResources(t *testing.T) {
	session := newFakeSession(func(requests <-chan string, respond func(string)) {
		for line := range requests {
			switch rpcMethod(line) {
			case "initialize":
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"minimal-server","version":"0.1.0"}}}`, string(rpcID(line))))
			case "notifications/initialized":
			case "tools/list":
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, string(rpcID(line))))
			case "prompts/list", "resources/list":
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}`, string(rpcID(line))))
			}
		}
	})
	defer session.Close()

	discovery, err := Discover(context.Background(), session, Options{})
	if err != nil {
		t.Fatalf("Discover should tolerate optional-capability method-not-found errors: %v", err)
	}
	if discovery.Prompts != nil || discovery.Resources != nil {
		t.Fatalf("expected no prompts/resources, got %#v / %#v", discovery.Prompts, discovery.Resources)
	}
}

// TestDiscoverFailsClosedOnHungServer proves a server that never replies
// doesn't block the caller forever — matching skil's fail-closed
// philosophy for every other timeout-bounded operation in this codebase.
func TestDiscoverFailsClosedOnHungServer(t *testing.T) {
	session := newFakeSession(func(requests <-chan string, respond func(string)) {
		for range requests {
			// never respond
		}
	})
	defer session.Close()

	start := time.Now()
	_, err := Discover(context.Background(), session, Options{Timeout: 50 * time.Millisecond})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected a timeout error from a hung server")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Discover took too long to fail closed: %s", elapsed)
	}
}

// TestDiscoverRejectsOversizedResponse proves a malicious/misbehaving
// server can't exhaust the caller by sending an arbitrarily large response
// frame.
func TestDiscoverRejectsOversizedResponse(t *testing.T) {
	session := newFakeSession(func(requests <-chan string, respond func(string)) {
		for line := range requests {
			switch rpcMethod(line) {
			case "initialize":
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"s","version":"1"}}}`, string(rpcID(line))))
			case "notifications/initialized":
			case "tools/list":
				respond(`{"jsonrpc":"2.0","id":` + string(rpcID(line)) + `,"result":{"tools":[{"name":"x","description":"` + strings.Repeat("A", 2<<20) + `"}]}}`)
			}
		}
	})
	defer session.Close()

	_, err := Discover(context.Background(), session, Options{MaxResponseBytes: 1024})
	if err == nil {
		t.Fatal("expected an error for an oversized response frame")
	}
}

func TestCompareToLockDetectsUndeclaredAndMismatchedTools(t *testing.T) {
	matchedDigest := sha256digest("Reads a file from the workspace.")
	staleDigest := sha256digest("a completely different, previously-reviewed description")
	discovery := Discovery{Tools: []Tool{
		{Name: "read_file", Description: "Reads a file from the workspace."},                         // matches lock
		{Name: "delete_file", Description: "Deletes any file without confirmation."},                 // undeclared
		{Name: "list_files", Description: "Lists files, now with hidden exfiltration instructions."}, // rug-pulled
	}}
	lock := map[string]string{
		"read_file":  matchedDigest,
		"list_files": staleDigest,
	}

	mismatches := CompareToLock(discovery, lock)
	if len(mismatches) != 2 {
		t.Fatalf("expected 2 mismatches, got %d: %#v", len(mismatches), mismatches)
	}
	byTool := map[string]Mismatch{}
	for _, m := range mismatches {
		byTool[m.Tool] = m
	}
	if byTool["delete_file"].Kind != MismatchUndeclared {
		t.Fatalf("expected delete_file undeclared, got %#v", byTool["delete_file"])
	}
	if byTool["list_files"].Kind != MismatchDigest || byTool["list_files"].ExpectedDescSHA256 != staleDigest {
		t.Fatalf("expected list_files digest mismatch, got %#v", byTool["list_files"])
	}
	if _, flagged := byTool["read_file"]; flagged {
		t.Fatal("read_file matches the lock and must not be reported")
	}
}

func sha256digest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// fakeStreamingProvider adapts newFakeSession to eval.StreamingIsolationProvider
// so Run's orchestration (Start -> Discover -> CompareToLock -> Close) is
// exercised end-to-end without a real OS sandbox.
type fakeStreamingProvider struct {
	serve func(<-chan string, func(string))
}

func (fakeStreamingProvider) ID() string { return "fake" }
func (fakeStreamingProvider) Run(context.Context, eval.IsolationRequest, io.Writer, io.Writer) error {
	return errors.New("not used by these tests")
}
func (p fakeStreamingProvider) Start(context.Context, eval.IsolationRequest) (eval.Session, error) {
	return newFakeSession(p.serve), nil
}

func TestRunEndToEndAgainstFakeStreamingProvider(t *testing.T) {
	provider := fakeStreamingProvider{serve: wellBehavedServer("Reads a file from the workspace.")}
	lock := map[string]string{"read_file": sha256digest("a stale, previously-reviewed description")}

	result, err := Run(context.Background(), provider, RunRequest{Executable: "fake-mcp-server"}, lock)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Passed() {
		t.Fatal("expected a rug-pull mismatch against the stale lock")
	}
	if len(result.Mismatches) != 1 || result.Mismatches[0].Kind != MismatchDigest {
		t.Fatalf("unexpected mismatches: %#v", result.Mismatches)
	}
}

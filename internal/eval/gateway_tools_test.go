package eval

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func TestArtifactReadToolUsesOnlyCanonicalArtifactView(t *testing.T) {
	tool := NewArtifactReadTool(skil.Artifact{Files: []skil.File{{Path: "docs/readme.md", Data: []byte("safe")}}})
	operation, err := tool.Operation(map[string]any{"path": "docs/readme.md"})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Capability != "filesystem.read" || operation.Target != "docs/readme.md" {
		t.Fatalf("unexpected operation: %#v", operation)
	}
	value, err := tool.Execute(context.Background(), map[string]any{"path": "docs/readme.md"})
	if err != nil || value.(map[string]any)["content"] != "safe" {
		t.Fatalf("unexpected result: %#v, %v", value, err)
	}
	for _, path := range []string{"../secret", "docs/../secret", "/etc/passwd"} {
		if _, err := tool.Operation(map[string]any{"path": path}); err == nil {
			t.Errorf("unsafe path %q accepted", path)
		}
	}
}

func TestWorkspaceToolsConfineReadAndWrite(t *testing.T) {
	root := t.TempDir()
	writeTool := NewWorkspaceWriteTool(root)
	arguments := map[string]any{"path": "results/report.txt", "content": "bounded"}
	operation, err := writeTool.Operation(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Capability != "filesystem.write" || operation.Target != "results/report.txt" {
		t.Fatalf("unexpected write operation: %#v", operation)
	}
	if _, err := writeTool.Execute(context.Background(), arguments); err != nil {
		t.Fatal(err)
	}
	value, err := NewWorkspaceReadTool(root).Execute(context.Background(), map[string]any{"path": "results/report.txt"})
	if err != nil || value.(map[string]any)["content"] != "bounded" {
		t.Fatalf("unexpected workspace read: %#v %v", value, err)
	}
	for _, path := range []string{"../escape", "results/../escape", "/tmp/escape"} {
		if _, err := writeTool.Operation(map[string]any{"path": path, "content": "x"}); err == nil {
			t.Errorf("unsafe workspace path %q accepted", path)
		}
	}
}

func TestWorkspaceToolsRejectSymlinkTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	tool := NewWorkspaceWriteTool(root)
	if _, err := tool.Execute(context.Background(), map[string]any{
		"path": "link/escaped.txt", "content": "blocked",
	}); err == nil {
		t.Fatal("workspace tool followed a symlink")
	}
}

func TestCommandToolDerivesStructuredOperationAndRejectsShells(t *testing.T) {
	tool := NewIsolatedCommandTool(nil, 1024)
	operation, err := tool.Operation(map[string]any{"argv": []any{"git", "status", "--short"}})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Capability != "commands.execute" || len(operation.Command) != 3 {
		t.Fatalf("unexpected command operation: %#v", operation)
	}
	for _, argv := range [][]any{{"sh", "-c", "id"}, {"git", "status\nwhoami"}, {}} {
		if _, err := tool.Operation(map[string]any{"argv": argv}); err == nil {
			t.Errorf("unsafe argv accepted: %#v", argv)
		}
	}
}

func TestNetworkGetToolDerivesBoundedExternalOperation(t *testing.T) {
	tool := NewNetworkGetTool()
	operation, err := tool.Operation(map[string]any{
		"url": "https://example.com/resource", "max_bytes": float64(4096),
	})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Capability != "network.outbound" || operation.Target != "example.com" ||
		operation.NetworkBytes != 4096 || !operation.External {
		t.Fatalf("unexpected network operation: %#v", operation)
	}
}

func TestNetworkGetToolRejectsUnsafeDestinationsAndArguments(t *testing.T) {
	tool := NewNetworkGetTool()
	cases := []map[string]any{
		{"url": "http://example.com"},
		{"url": "https://user:pass@example.com"},
		{"url": "https://example.com:8443"},
		{"url": "https://127.0.0.1"},
		{"url": "https://[::1]"},
		{"url": "https://example.com", "max_bytes": float64(0)},
		{"url": "https://example.com", "unexpected": true},
	}
	for _, arguments := range cases {
		if _, err := tool.Operation(arguments); err == nil {
			t.Errorf("unsafe network arguments accepted: %#v", arguments)
		}
	}
}

func TestPublicIPClassification(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "192.0.2.1", "::1", "fc00::1"} {
		if publicIP(net.ParseIP(value)) {
			t.Errorf("non-public address classified as public: %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(net.ParseIP(value)) {
			t.Errorf("public address classified as non-public: %s", value)
		}
	}
}

type sequenceResolver struct {
	responses [][]net.IP
	calls     int
}

func (r *sequenceResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	index := r.calls
	r.calls++
	if index >= len(r.responses) {
		return nil, errors.New("unexpected lookup")
	}
	return r.responses[index], nil
}

func TestNetworkGetToolRejectsDNSRebindingBeforeDial(t *testing.T) {
	resolver := &sequenceResolver{responses: [][]net.IP{
		{net.ParseIP("8.8.8.8")},
		{net.ParseIP("127.0.0.1")},
	}}
	dialed := false
	tool := &NetworkGetTool{
		resolver: resolver,
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not dial")
		},
	}
	_, err := tool.Execute(context.Background(), map[string]any{"url": "https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "non-public") || dialed || resolver.calls != 2 {
		t.Fatalf("DNS rebinding was not rejected before dial: err=%v dialed=%v calls=%d", err, dialed, resolver.calls)
	}
}

type cancelingResolver struct {
	entered chan struct{}
	calls   int
}

func (r *cancelingResolver) LookupIP(ctx context.Context, _ string, _ string) ([]net.IP, error) {
	r.calls++
	if r.calls == 1 {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}
	close(r.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestNetworkGetToolCancelsDuringDialResolution(t *testing.T) {
	resolver := &cancelingResolver{entered: make(chan struct{})}
	tool := &NetworkGetTool{resolver: resolver}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := tool.Execute(ctx, map[string]any{"url": "https://example.com"})
		done <- err
	}()
	select {
	case <-resolver.entered:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("network tool did not reach dial-time resolution")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("network cancellation returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("network tool ignored cancellation")
	}
}

func TestNetworkGetToolPublicHTTPSIntegration(t *testing.T) {
	destination := os.Getenv("SKIL_TEST_NETWORK_GATEWAY_URL")
	if destination == "" {
		t.Skip("set SKIL_TEST_NETWORK_GATEWAY_URL to exercise a public HTTPS endpoint")
	}
	value, err := NewNetworkGetTool().Execute(context.Background(), map[string]any{
		"url": destination, "max_bytes": float64(64 << 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, ok := value.(map[string]any)
	if !ok || result["status"] != 200 || result["body"] == "" {
		t.Fatalf("unexpected public HTTPS result: %#v", value)
	}
}

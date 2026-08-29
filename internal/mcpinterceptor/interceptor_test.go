package mcpinterceptor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInterceptorBlocksUnauthorizedDynamicTool(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "mcp-surface.lock.json")
	lockContent := `{"version": 1, "tools": {"safe_tool": "sha256:123"}}`
	if err := os.WriteFile(lockPath, []byte(lockContent), 0644); err != nil {
		t.Fatal(err)
	}

	interceptor, err := NewInterceptor(InterceptorOptions{
		SurfaceLockPath: lockPath,
		Strict:          true,
	})
	if err != nil {
		t.Fatalf("NewInterceptor failed: %v", err)
	}

	// 1. Authorized tool call
	safeCall := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool"}}`)
	res, err := interceptor.FilterMessage(safeCall, true)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(res, []byte("BLOCKED")) {
		t.Fatalf("expected safe tool call to be allowed")
	}

	// 2. Unauthorized dynamic tool call
	unauthorizedCall := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unauthorized_shell"}}`)
	res, err = interceptor.FilterMessage(unauthorizedCall, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(res, []byte("BLOCKED")) {
		t.Fatalf("expected unauthorized tool call to be blocked by interceptor")
	}
}

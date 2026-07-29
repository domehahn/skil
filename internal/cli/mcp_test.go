package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPStdioListsToolsAndConfinesPaths(t *testing.T) {
	root := t.TempDir()
	requests := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"skil_scan","arguments":{"path":"../escape"}}}`,
	}, "\n") + "\n"
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	app.In = strings.NewReader(requests)
	if code := app.Run(context.Background(), []string{"serve", "--stdio", "--root", root}); code != ExitOK {
		t.Fatalf("serve failed: %d %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "skil_scan") || !strings.Contains(lines[2], "escapes") {
		t.Fatalf("unexpected MCP responses: %s", out.String())
	}
}

func TestMCPHTTPRequiresBearerToken(t *testing.T) {
	root := t.TempDir()
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	handler := app.mcpHTTPHandler(context.Background(), root, strings.Repeat("x", 32))
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	authorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK || !strings.Contains(authorized.Body.String(), "skil_scan") {
		t.Fatalf("authorized response=%d %s", authorized.Code, authorized.Body.String())
	}
}

func TestMCPPathRejectsIntermediateSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "SKILL.md"), []byte("# outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := confinedMCPPath(root, "linked"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("intermediate symlink escape was not rejected: %v", err)
	}
}

func TestScanAllReturnsOneResultPerSkill(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"one", "two"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("# "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	if code := New(&out, &errOut).Run(context.Background(), []string{"scan-all", root, "--format", "json", "--workers", "2"}); code != ExitOK {
		t.Fatalf("scan-all failed: %d %s", code, errOut.String())
	}
	var result struct {
		Skills []json.RawMessage `json:"skills"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Skills) != 2 {
		t.Fatalf("unexpected collection output: %s", out.String())
	}
}

func TestScanAllRejectsUnsafeWorkerCount(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"scan-all", t.TempDir(), "--workers", "0"})
	if code != ExitInput || !strings.Contains(errOut.String(), "--workers") {
		t.Fatalf("invalid worker count result=%d stderr=%q", code, errOut.String())
	}
}

func TestScanAllMarkdownOutput(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("# one"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"scan-all", root, "--format", "markdown"})
	if code != ExitOK || !strings.Contains(out.String(), "| Skill | Status |") {
		t.Fatalf("markdown collection result=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

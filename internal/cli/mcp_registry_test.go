package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPRegistryScanCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	content := `{"$schema":"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json","name":"io.github.example/weather","description":"Weather","version":"1.0.0","repository":{"url":"https://github.com/example/weather","source":"github"},"packages":[{"registryType":"npm","identifier":"@example/weather","version":"1.0.0"}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"mcp", "registry", "scan", path, "--format", "json"})
	if code != ExitOK {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
	var report struct {
		Summary struct {
			Passed bool `json:"passed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || !report.Summary.Passed {
		t.Fatalf("invalid report: err=%v output=%s", err, out.String())
	}
}

func TestMCPRegistryScanReturnsGateFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	content := `{"$schema":"x","name":"io.github.example/weather","description":"Weather","version":"latest","remotes":[{"type":"sse","url":"http://example.test/mcp"}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"mcp", "registry", "scan", path})
	if code != ExitGateFail || !strings.Contains(out.String(), "MCP-REG-002") || !strings.Contains(out.String(), "MCP-REG-008") {
		t.Fatalf("unexpected gate result: code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
}

func TestMCPRegistryScanRejectsSymlinkInput(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	link := filepath.Join(root, "link.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"mcp", "registry", "scan", link})
	if code != ExitInput || !strings.Contains(errOut.String(), "non-symlink") {
		t.Fatalf("symlink input was accepted: code=%d stderr=%s", code, errOut.String())
	}
}

func TestMCPRegistryScanDoesNotOverwriteInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	content := []byte(`{"$schema":"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json","name":"io.github.example/weather","version":"1.0.0","remotes":[{"type":"sse","url":"https://example.test/mcp"}]}`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"mcp", "registry", "scan", path, "--output", path})
	if code != ExitInput || !strings.Contains(errOut.String(), "must not overwrite") {
		t.Fatalf("input overwrite was accepted: code=%d stderr=%s", code, errOut.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("input changed: err=%v got=%q", err, got)
	}
}

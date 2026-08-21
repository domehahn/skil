package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPAssureRequiresRuntimeCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{"mcp", "assure", fixture(t, "example")})
	if code != ExitInput || !strings.Contains(stderr.String(), "--runtime-command") {
		t.Fatalf("mcp assure accepted no runtime command: code=%d stderr=%s", code, stderr.String())
	}
}

func TestMCPAssureRequiresLock(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"mcp", "assure", fixture(t, "example"), "--runtime-command", "/synthetic/mcp-server",
	})
	if code != ExitInput || !strings.Contains(stderr.String(), "mcp-tools.lock.json") {
		t.Fatalf("mcp assure accepted a skill with no metadata lock: code=%d stderr=%s", code, stderr.String())
	}
}

// TestMCPAssureDetectsRugPullAgainstRealSandbox proves `skil mcp assure`
// end-to-end: it launches a real MCP server (this test binary, self-exec'd
// into TestMCPServerHelper) inside the real native OS sandbox, performs the
// actual JSON-RPC handshake, and flags the tool whose live description
// disagrees with a deliberately stale .skil/mcp-tools.lock.json. Gated the
// same way as internal/eval's own native-sandbox integration tests, since
// it depends on a real sandbox-exec/bwrap/AppContainer helper being present.
func TestMCPAssureDetectsRugPullAgainstRealSandbox(t *testing.T) {
	if os.Getenv("SKIL_REQUIRE_NATIVE_ISOLATION") != "1" {
		t.Skip("native isolation integration test requires SKIL_REQUIRE_NATIVE_ISOLATION=1")
	}
	skillDir := t.TempDir()
	writeMCPAssureFixtureSkill(t, skillDir)

	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"mcp", "assure", skillDir,
		"--runtime-command", os.Args[0],
		"--runtime-args", "-test.run=TestMCPServerHelper,--,mcp-server",
		"--format", "json",
	})
	if code != ExitGateFail {
		t.Fatalf("expected a gate failure for the rug-pulled tool: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var result mcpAssuranceResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parse mcp assure JSON output: %v\n%s", err, stdout.String())
	}
	if result.Passed || result.ServerName != "fixture-mcp-server" || len(result.Mismatches) != 1 {
		t.Fatalf("unexpected assurance result: %#v", result)
	}
	if result.Mismatches[0].Tool != "read_file" || result.Mismatches[0].Kind != "digest_mismatch" {
		t.Fatalf("unexpected mismatch: %#v", result.Mismatches[0])
	}
}

func writeMCPAssureFixtureSkill(t *testing.T, dir string) {
	t.Helper()
	skillMD := "# Fixture skill for mcp assure\n\nUsed only to exercise skil mcp assure end-to-end.\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillMD), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".skil"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A deliberately stale digest for "read_file" (the live server below
	// reports a different description), proving the comparison actually
	// runs against real, observed metadata rather than trivially passing.
	stale := strings.Repeat("a", 64)
	document := fmt.Sprintf(`{"version":1,"tools":{"read_file":%q}}`, stale)
	if err := os.WriteFile(filepath.Join(dir, ".skil", "mcp-tools.lock.json"), []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestMCPServerHelper is a real, self-exec'd MCP server speaking the
// actual JSON-RPC-over-stdio protocol skil's client drives — see
// TestMCPAssureDetectsRugPullAgainstRealSandbox.
func TestMCPServerHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[1] != "-test.run=TestMCPServerHelper" {
		return
	}
	found := false
	for _, argument := range os.Args {
		if argument == "mcp-server" {
			found = true
		}
	}
	if !found {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	writer := bufio.NewWriter(os.Stdout)
	for scanner.Scan() {
		var envelope struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil {
			continue
		}
		switch envelope.Method {
		case "initialize":
			fmt.Fprintf(writer, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2025-06-18\",\"serverInfo\":{\"name\":\"fixture-mcp-server\",\"version\":\"1.0.0\"}}}\n", string(envelope.ID))
		case "notifications/initialized":
			continue
		case "tools/list":
			fmt.Fprintf(writer, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"tools\":[{\"name\":\"read_file\",\"description\":\"Reads a file from the workspace and returns its contents.\"}]}}\n", string(envelope.ID))
		case "prompts/list":
			fmt.Fprintf(writer, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"prompts\":[]}}\n", string(envelope.ID))
		case "resources/list":
			fmt.Fprintf(writer, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"resources\":[]}}\n", string(envelope.ID))
		default:
			continue
		}
		writer.Flush()
	}
	os.Exit(0)
}

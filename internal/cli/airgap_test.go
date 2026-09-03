package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestAirgapRejectsEachNetworkCapableFlag proves --airgap is a genuine
// single authoritative gate: every network-capable flag it must catch is
// exercised individually, and the failure happens before any work starts
// (ExitInput, not a partial scan).
func TestAirgapRejectsEachNetworkCapableFlag(t *testing.T) {
	skill := fixture(t, "clean-skill")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"full", []string{"scan", skill, "--airgap", "--full"}, "--full"},
		{"osv-without-offline", []string{"scan", skill, "--airgap", "--osv"}, "--osv-offline"},
		{"semantic-without-private", []string{"scan", skill, "--airgap", "--semantic", "--semantic-model", "x"}, "--semantic-allow-private"},
		{"allow-remote", []string{"scan", skill, "--airgap", "--allow-remote"}, "--allow-remote"},
		{"transitive", []string{"scan", skill, "--airgap", "--transitive"}, "--transitive"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := New(&out, &errOut).Run(context.Background(), test.args)
			if code != ExitInput {
				t.Fatalf("expected ExitInput, got %d (stdout=%s stderr=%s)", code, out.String(), errOut.String())
			}
			if !strings.Contains(errOut.String(), test.want) {
				t.Fatalf("expected the rejection message to name %q, got stderr=%s", test.want, errOut.String())
			}
			if out.Len() != 0 {
				t.Fatalf("--airgap must fail before producing any scan output, got stdout=%s", out.String())
			}
		})
	}
}

// TestAirgapAllowsOfflineSafeEquivalents proves --airgap is not simply "no
// --osv/--semantic at all" — it accepts the offline-safe form of each flag
// and only blocks the network-requiring one.
func TestAirgapAllowsOfflineSafeEquivalents(t *testing.T) {
	skill := fixture(t, "clean-skill")
	// A cache path that doesn't exist yet is a legitimate first-time
	// offline setup (internal/provider/osv treats a missing cache file as
	// zero entries, not an error) — no need to pre-populate one here.
	cache := t.TempDir() + "/osv-cache.json"
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{
		"scan", skill, "--airgap", "--osv", "--osv-offline", "--osv-cache", cache, "--format", "json",
	})
	if code != ExitOK {
		t.Fatalf("expected --airgap to accept --osv with --osv-offline, got code=%d stderr=%s", code, errOut.String())
	}
}

func TestAirgapWithoutAnyNetworkFlagIsANoOp(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"scan", fixture(t, "clean-skill"), "--airgap", "--format", "json"})
	if code != ExitOK {
		t.Fatalf("expected an ordinary offline scan to pass under --airgap: code=%d stderr=%s", code, errOut.String())
	}
}

func TestMCPRegistryAirgapRejectsOfficial(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"mcp", "registry", "scan", "--airgap", "--official"})
	if code != ExitInput || !strings.Contains(errOut.String(), "--official") {
		t.Fatalf("expected --airgap to reject --official: code=%d stderr=%s", code, errOut.String())
	}
}

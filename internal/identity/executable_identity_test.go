package identity

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestBuildExecutableIdentity_CrossEcosystem(t *testing.T) {
	tests := []struct {
		eco            ExecutableEcosystem
		module         string
		symbol         string
		subcommand     string
		expectedCanon string
	}{
		{EcosystemPython, "os", "system", "", "python://os/system"},
		{EcosystemShell, "", "curl", "-X POST", "shell://curl/-X POST"},
		{EcosystemMCPTool, "git-mcp", "git_commit", "", "mcp_tool://git-mcp/git_commit"},
		{EcosystemNative, "usr/bin", "tar", "extract", "native://usr/bin/tar/extract"},
	}

	for _, tt := range tests {
		execId := BuildExecutableIdentity(tt.eco, tt.module, tt.symbol, tt.subcommand, nil)
		if execId.Canonical != tt.expectedCanon {
			t.Errorf("BuildExecutableIdentity(%s, %s, %s, %s) canonical = %s; want %s",
				tt.eco, tt.module, tt.symbol, tt.subcommand, execId.Canonical, tt.expectedCanon)
		}
	}
}

func TestFromCallableIdentity_Conversion(t *testing.T) {
	ci := skil.CallableIdentity{
		Ecosystem:  "python",
		Module:     "subprocess",
		Symbol:     "run",
		Canonical:  "python://stdlib/subprocess/run",
		Provenance: []string{"import subprocess as sp", "sp.run"},
	}

	execId := FromCallableIdentity(ci)
	if execId.Ecosystem != EcosystemPython {
		t.Errorf("Expected EcosystemPython, got %s", execId.Ecosystem)
	}

	if execId.Canonical != "python://subprocess/run" {
		t.Errorf("Unexpected canonical identity: %s", execId.Canonical)
	}
}

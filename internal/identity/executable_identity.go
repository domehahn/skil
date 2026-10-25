package identity

import (
	"fmt"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// ExecutableEcosystem identifies the technology domain of an executable identity.
type ExecutableEcosystem string

const (
	EcosystemPython     ExecutableEcosystem = "python"
	EcosystemJavaScript ExecutableEcosystem = "javascript"
	EcosystemTypeScript ExecutableEcosystem = "typescript"
	EcosystemShell      ExecutableEcosystem = "shell"
	EcosystemPowerShell ExecutableEcosystem = "powershell"
	EcosystemMCPTool    ExecutableEcosystem = "mcp_tool"
	EcosystemAgentTool  ExecutableEcosystem = "agent_tool"
	EcosystemNative     ExecutableEcosystem = "native"
)

// ExecutableIdentity generalizes CallableIdentity into a cross-ecosystem executable identity model.
type ExecutableIdentity struct {
	Ecosystem  ExecutableEcosystem `json:"ecosystem" yaml:"ecosystem"`
	Module     string              `json:"module,omitempty" yaml:"module,omitempty"`
	Symbol     string              `json:"symbol" yaml:"symbol"`
	Subcommand string              `json:"subcommand,omitempty" yaml:"subcommand,omitempty"`
	Canonical  string              `json:"canonical" yaml:"canonical"`
	Provenance []string            `json:"provenance,omitempty" yaml:"provenance,omitempty"`
	Resolution string              `json:"resolution" yaml:"resolution"`
}

// BuildExecutableIdentity creates a canonical ExecutableIdentity across any supported ecosystem.
func BuildExecutableIdentity(eco ExecutableEcosystem, module, symbol, subcommand string, provenance []string) ExecutableIdentity {
	modClean := strings.TrimSpace(module)
	symClean := strings.TrimSpace(symbol)
	subClean := strings.TrimSpace(subcommand)

	canonical := fmt.Sprintf("%s://", eco)
	if modClean != "" {
		canonical += modClean + "/"
	}
	canonical += symClean
	if subClean != "" {
		canonical += "/" + subClean
	}

	return ExecutableIdentity{
		Ecosystem:  eco,
		Module:     modClean,
		Symbol:     symClean,
		Subcommand: subClean,
		Canonical:  canonical,
		Provenance: provenance,
		Resolution: "EXACT",
	}
}

// FromCallableIdentity converts a legacy skil.CallableIdentity into an ExecutableIdentity.
func FromCallableIdentity(ci skil.CallableIdentity) ExecutableIdentity {
	eco := ExecutableEcosystem(strings.ToLower(ci.Ecosystem))
	if eco == "" {
		eco = EcosystemPython
	}
	return BuildExecutableIdentity(eco, ci.Module, ci.Symbol, "", ci.Provenance)
}

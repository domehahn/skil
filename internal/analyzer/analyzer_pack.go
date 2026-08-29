package analyzer

import (
	"errors"
	"fmt"
	"strings"
)

// AnalyzerPack defines the explicit metadata model and trust boundary for third-party or external analyzer extensions.
type AnalyzerPack struct {
	ID                 string   `json:"id" yaml:"id"`
	Version            string   `json:"version" yaml:"version"`
	SHA256             string   `json:"sha256" yaml:"sha256"`
	Signer             string   `json:"signer,omitempty" yaml:"signer,omitempty"`
	SupportedTypes     []string `json:"supported_file_types" yaml:"supported_file_types"`
	AnalysisTypes      []string `json:"analysis_types" yaml:"analysis_types"`
	RequiredProviders  []string `json:"required_providers,omitempty" yaml:"required_providers,omitempty"`
	DeclaredNetworkReq bool     `json:"declared_network_requirement,omitempty" yaml:"declared_network_requirement,omitempty"`
}

// ValidatePackTrust verifies that an analyzer pack matches policy allowlist requirements.
func ValidatePackTrust(pack AnalyzerPack, allowlist []AnalyzerPack) error {
	if pack.ID == "" || pack.Version == "" || len(pack.SHA256) != 64 {
		return errors.New("analyzer pack metadata or sha256 digest is incomplete")
	}

	for _, allowed := range allowlist {
		if allowed.ID == pack.ID && allowed.Version == pack.Version {
			if !strings.EqualFold(allowed.SHA256, pack.SHA256) {
				return fmt.Errorf("analyzer pack %s@%s digest %s does not match allowed digest %s", pack.ID, pack.Version, pack.SHA256, allowed.SHA256)
			}
			return nil
		}
	}
	return fmt.Errorf("analyzer pack %s@%s is not in policy allowlist", pack.ID, pack.Version)
}

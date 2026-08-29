package contracts

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"github.com/domehahn/skil/schemas"
	"gopkg.in/yaml.v3"
)

var names = []string{"skill.yaml", "skill.yml", "skil.yaml", "skil.yml", ".skil/contract.yaml"}

type Format string

const (
	FormatNative    Format = "skil-contract"
	FormatPortable  Format = "portable-contract"
	FormatUniversal Format = "universal-skill-manifest"
)

func Find(artifact skil.Artifact) (*skil.SkillContract, string, error) {
	contract, path, _, err := FindWithFormat(artifact)
	return contract, path, err
}

func FindWithFormat(artifact skil.Artifact) (*skil.SkillContract, string, Format, error) {
	for _, file := range artifact.Files {
		for _, name := range names {
			if strings.EqualFold(filepath.ToSlash(file.Path), name) {
				contract, format, err := ParseWithFormat(file.Data)
				if err != nil {
					return nil, file.Path, "", fmt.Errorf("parse contract: %w", err)
				}
				return &contract, file.Path, format, nil
			}
		}
	}
	return nil, "", "", errors.New("no skill contract found (expected skill.yaml or skil.yaml)")
}

func Parse(data []byte) (skil.SkillContract, error) {
	contract, _, err := ParseWithFormat(data)
	return contract, err
}

func ParseWithFormat(data []byte) (skil.SkillContract, Format, error) {
	var shape map[string]any
	if err := yaml.Unmarshal(data, &shape); err != nil {
		return skil.SkillContract{}, "", err
	}
	if _, native := shape["skill"]; native {
		var c skil.SkillContract
		if err := strictYAML(data, &c); err != nil {
			return c, FormatNative, err
		}
		return c, FormatNative, Validate(c)
	}
	if isUniversalManifest(shape) {
		contract, err := parseUniversal(data)
		return contract, FormatUniversal, err
	}
	contract, err := parsePortable(data)
	return contract, FormatPortable, err
}

type portableContract struct {
	ContractVersion int                  `json:"contract_version" yaml:"contract_version"`
	Name            string               `json:"name" yaml:"name"`
	Version         string               `json:"version" yaml:"version"`
	Description     string               `json:"description" yaml:"description"`
	Owner           string               `json:"owner" yaml:"owner"`
	Entrypoint      string               `json:"entrypoint" yaml:"entrypoint"`
	Compatibility   *skil.Compatibility  `json:"compatibility,omitempty" yaml:"compatibility,omitempty"`
	Security        skil.SecurityPosture `json:"security" yaml:"security"`
	Capabilities    *skil.Capabilities   `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
}

type universalManifest struct {
	Name           string   `json:"name" yaml:"name"`
	Version        string   `json:"version" yaml:"version"`
	Description    string   `json:"description" yaml:"description"`
	Entrypoint     string   `json:"entrypoint" yaml:"entrypoint"`
	License        string   `json:"license,omitempty" yaml:"license,omitempty"`
	Owners         []string `json:"owners" yaml:"owners"`
	CompatibleWith []string `json:"compatible_with,omitempty" yaml:"compatible_with,omitempty"`
}

func isUniversalManifest(shape map[string]any) bool {
	_, owners := shape["owners"]
	_, compatible := shape["compatible_with"]
	_, license := shape["license"]
	return owners || compatible || license
}

func parseUniversal(data []byte) (skil.SkillContract, error) {
	if err := schemas.ValidateYAML("universal-skill-manifest-v1.schema.json", data); err != nil {
		return skil.SkillContract{}, err
	}
	var manifest universalManifest
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return skil.SkillContract{}, err
	}
	contract := skil.SkillContract{
		Version: 1,
		Skill: skil.SkillIdentity{
			Name: manifest.Name, Version: manifest.Version, Description: manifest.Description,
		},
		Owner: manifest.Owners[0], Entrypoint: manifest.Entrypoint,
		Compatibility: &skil.Compatibility{Agents: manifest.CompatibleWith},
		Security:      &skil.SecurityPosture{},
		Capabilities: skil.Capabilities{
			Agent: skil.AgentCapability{ConfirmDestructive: true, ConfirmExternal: true},
		},
	}
	return contract, Validate(contract)
}

func parsePortable(data []byte) (skil.SkillContract, error) {
	if err := schemas.ValidateYAML("portable-skill-contract-v1.schema.json", data); err != nil {
		return skil.SkillContract{}, err
	}
	var portable portableContract
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&portable); err != nil {
		return skil.SkillContract{}, err
	}
	capabilities := skil.Capabilities{Agent: skil.AgentCapability{ConfirmDestructive: true, ConfirmExternal: true}}
	if portable.Capabilities != nil {
		capabilities = *portable.Capabilities
	} else if portable.Security.RequiresNetwork || portable.Security.RequiresSecrets ||
		portable.Security.WritesFiles || portable.Security.RunsCommands {
		return skil.SkillContract{}, errors.New("portable contracts with active security capabilities require a detailed capabilities section")
	}
	contract := skil.SkillContract{
		Version: 1, Skill: skil.SkillIdentity{Name: portable.Name, Version: portable.Version, Description: portable.Description},
		Owner: portable.Owner, Entrypoint: portable.Entrypoint, Compatibility: portable.Compatibility,
		Security: &portable.Security, Capabilities: capabilities,
	}
	return contract, Validate(contract)
}

func Validate(c skil.SkillContract) error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported contract version %d", c.Version)
	}
	if strings.TrimSpace(c.Skill.Name) == "" {
		return errors.New("skill.name is required")
	}
	if strings.TrimSpace(c.Skill.Description) == "" {
		return errors.New("skill.description is required")
	}
	if c.Security != nil {
		if c.Security.RequiresNetwork != c.Capabilities.Network.Outbound {
			return errors.New("security.requires_network must match capabilities.network.outbound")
		}
		if c.Security.RequiresSecrets != (len(c.Capabilities.Secrets.Read) > 0) {
			return errors.New("security.requires_secrets must match capabilities.secrets.read")
		}
		if c.Security.WritesFiles != (len(c.Capabilities.Filesystem.Write) > 0 || len(c.Capabilities.Filesystem.Delete) > 0) {
			return errors.New("security.writes_files must match filesystem write/delete capabilities")
		}
		if c.Security.RunsCommands != c.Capabilities.Commands.Execute {
			return errors.New("security.runs_commands must match capabilities.commands.execute")
		}
	}
	if c.Capabilities.Network.Outbound && len(c.Capabilities.Network.Hosts) == 0 {
		return errors.New("network.outbound requires an explicit hosts allowlist")
	}
	if c.Capabilities.Commands.Execute && len(c.Capabilities.Commands.Allow) == 0 {
		return errors.New("commands.execute requires an explicit command allowlist")
	}
	seen := map[string]bool{}
	if c.ReviewedRootDigest != "" && !validSHA256(c.ReviewedRootDigest) {
		return errors.New("reviewed_root_digest requires a 64-character hexadecimal sha256 digest")
	}
	if c.ReviewedClosureDigest != "" {
		value := strings.TrimPrefix(c.ReviewedClosureDigest, "sha256:")
		if !validSHA256(value) {
			return errors.New("reviewed_closure_digest requires a sha256:<64 hexadecimal characters> digest")
		}
	}
	for _, dependency := range c.ReviewedClosure {
		if strings.TrimSpace(dependency.Identifier) == "" {
			return errors.New("reviewed_closure entries require a non-empty identifier")
		}
		if seen[dependency.Identifier] {
			return fmt.Errorf("reviewed_closure has a duplicate identifier %q", dependency.Identifier)
		}
		seen[dependency.Identifier] = true
		if !validSHA256(dependency.SHA256) {
			return fmt.Errorf("reviewed_closure entry %q requires a 64-character sha256 digest", dependency.Identifier)
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return true
}

func strictYAML(data []byte, target any) error {
	if err := schemas.ValidateYAML("skill-contract-v1.schema.json", data); err != nil {
		return err
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

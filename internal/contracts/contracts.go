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

func Find(artifact skil.Artifact) (*skil.SkillContract, string, error) {
	for _, file := range artifact.Files {
		for _, name := range names {
			if strings.EqualFold(filepath.ToSlash(file.Path), name) {
				var contract skil.SkillContract
				if err := strictYAML(file.Data, &contract); err != nil {
					return nil, file.Path, fmt.Errorf("parse contract: %w", err)
				}
				if err := Validate(contract); err != nil {
					return nil, file.Path, err
				}
				return &contract, file.Path, nil
			}
		}
	}
	return nil, "", errors.New("no skill contract found (expected skil.yaml)")
}

func Parse(data []byte) (skil.SkillContract, error) {
	var c skil.SkillContract
	if err := strictYAML(data, &c); err != nil {
		return c, err
	}
	return c, Validate(c)
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
	return nil
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

func validateShape(data []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("contract must be a YAML mapping")
	}
	root := document.Content[0]
	if err := requireMappingKeys(root, "contract", "version", "skill", "capabilities"); err != nil {
		return err
	}
	skill := mappingValue(root, "skill")
	if err := requireMappingKeys(skill, "skill", "name", "description"); err != nil {
		return err
	}
	capabilities := mappingValue(root, "capabilities")
	for _, key := range []string{"filesystem", "network", "commands", "secrets", "environment", "tools", "mcp", "persistence", "agent", "resources"} {
		if mappingValue(capabilities, key) == nil {
			return fmt.Errorf("capabilities.%s is required", key)
		}
	}
	required := map[string][]string{
		"filesystem":  {"read", "write", "delete"},
		"network":     {"inbound", "outbound", "hosts"},
		"commands":    {"execute", "allow"},
		"secrets":     {"read", "expose"},
		"environment": {"read"},
		"tools":       {"allow", "deny"},
		"mcp":         {"servers", "tools"},
		"agent":       {"autonomous_actions", "external_side_effects", "confirm_destructive", "confirm_external"},
	}
	for section, keys := range required {
		if err := requireMappingKeys(mappingValue(capabilities, section), "capabilities."+section, keys...); err != nil {
			return err
		}
	}
	return nil
}

func requireMappingKeys(node *yaml.Node, name string, keys ...string) error {
	if node == nil || node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be a mapping", name)
	}
	for _, key := range keys {
		if mappingValue(node, key) == nil {
			return fmt.Errorf("%s.%s is required", name, key)
		}
	}
	return nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

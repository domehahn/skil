package remediation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/domehahn/skil/internal/discover"
	"github.com/domehahn/skil/internal/mcpassure"
)

type FixResult struct {
	WorkspaceRoot string   `json:"workspace_root"`
	FilesModified []string `json:"files_modified"`
	ActionsTaken  []string `json:"actions_taken"`
	DryRun        bool     `json:"dry_run"`
}

// FixWorkspace performs automated remediation of dangerous agent configs
// and generates/updates .skil/mcp-surface.lock.json.
func FixWorkspace(workspaceRoot string, dryRun bool) (FixResult, error) {
	cleanRoot := filepath.Clean(workspaceRoot)
	result := FixResult{
		WorkspaceRoot: cleanRoot,
		DryRun:        dryRun,
	}

	locations := discover.WorkspaceLocations()
	for _, loc := range locations {
		targetPath := filepath.Join(cleanRoot, loc.RelPath)
		info, err := os.Lstat(targetPath)
		if os.IsNotExist(err) || err != nil || !info.Mode().IsRegular() {
			continue
		}

		data, err := os.ReadFile(targetPath)
		if err != nil {
			continue
		}

		modifiedData, actions, err := sanitizeAgentConfigData(data, loc.RelPath)
		if err != nil || len(actions) == 0 {
			continue
		}

		result.FilesModified = append(result.FilesModified, loc.RelPath)
		result.ActionsTaken = append(result.ActionsTaken, actions...)

		if !dryRun {
			if err := os.WriteFile(targetPath, modifiedData, info.Mode().Perm()); err != nil {
				return result, fmt.Errorf("write remediated config %s: %w", loc.RelPath, err)
			}
		}
	}

	// Lock surface if workspace components exist
	components, err := discover.DiscoverWorkspace(cleanRoot)
	if err == nil && len(components) > 0 {
		surfaceLockPath := filepath.Join(cleanRoot, ".skil", "mcp-surface.lock.json")
		var lockTools = make(map[string]string)
		for _, comp := range components {
			if comp.Kind == discover.KindMCPServer && comp.Command != "" {
				toolDig, _ := mcpassure.ToolDigest(mcpassure.Tool{Name: comp.Name, Description: "Auto-locked MCP tool " + comp.Name})
				lockTools[comp.Name] = toolDig
			}
		}
		if len(lockTools) > 0 {
			lockDoc := map[string]any{
				"version": 1,
				"tools":   lockTools,
			}
			lockBytes, _ := json.MarshalIndent(lockDoc, "", "  ")
			result.FilesModified = append(result.FilesModified, ".skil/mcp-surface.lock.json")
			result.ActionsTaken = append(result.ActionsTaken, fmt.Sprintf("generated .skil/mcp-surface.lock.json with %d tools", len(lockTools)))

			if !dryRun {
				_ = os.MkdirAll(filepath.Join(cleanRoot, ".skil"), 0755)
				_ = os.WriteFile(surfaceLockPath, lockBytes, 0644)
			}
		}
	}

	sort.Strings(result.FilesModified)
	return result, nil
}

func sanitizeAgentConfigData(data []byte, relPath string) ([]byte, []string, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&doc); err != nil {
		return data, nil, nil
	}

	var actions []string

	// 1. Sanitize bypassPermissions
	if bypass, ok := doc["bypassPermissions"].(bool); ok && bypass {
		doc["bypassPermissions"] = false
		actions = append(actions, fmt.Sprintf("%s: set bypassPermissions=false", relPath))
	}

	// 2. Sanitize autoApprove: ["*"]
	if autoApprove, ok := doc["autoApprove"].([]any); ok {
		var newApprove []any
		for _, item := range autoApprove {
			if str, ok := item.(string); ok && str == "*" {
				actions = append(actions, fmt.Sprintf("%s: removed wildcard '*' from autoApprove", relPath))
			} else {
				newApprove = append(newApprove, item)
			}
		}
		doc["autoApprove"] = newApprove
	}

	if len(actions) == 0 {
		return data, nil, nil
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return data, nil, err
	}
	return out, actions, nil
}

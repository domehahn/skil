package discover

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type InfraComponent struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // "runtime", "server", "framework"
	Version string `json:"version"`
	Path    string `json:"path"`
}

// DiscoverInfra probes for local AI execution runtimes and server configs.
func DiscoverInfra(workspaceRoot string) ([]InfraComponent, error) {
	cleanRoot := filepath.Clean(workspaceRoot)
	var components []InfraComponent

	// 1. Ollama local runtime
	if ollamaPath, err := exec.LookPath("ollama"); err == nil {
		out, err := exec.Command(ollamaPath, "--version").Output()
		version := "0.0.0"
		if err == nil {
			version = strings.TrimSpace(strings.TrimPrefix(string(out), "ollama version is "))
		}
		components = append(components, InfraComponent{
			Name:    "ollama",
			Kind:    "runtime",
			Version: version,
			Path:    ollamaPath,
		})
	}

	// 2. ComfyUI / Local AI workspace configs
	comfyConfig := filepath.Join(cleanRoot, "comfyui_config.json")
	if info, err := os.Stat(comfyConfig); err == nil && info.Mode().IsRegular() {
		components = append(components, InfraComponent{
			Name:    "comfyui",
			Kind:    "framework",
			Version: "workspace-config",
			Path:    comfyConfig,
		})
	}

	// 3. OpenCode / Local AI Configs
	opencodeConfig := filepath.Join(cleanRoot, "opencode.json")
	if info, err := os.Stat(opencodeConfig); err == nil && info.Mode().IsRegular() {
		var doc map[string]any
		data, _ := os.ReadFile(opencodeConfig)
		_ = json.Unmarshal(data, &doc)
		model, _ := doc["model"].(string)

		components = append(components, InfraComponent{
			Name:    "opencode",
			Kind:    "server",
			Version: model,
			Path:    opencodeConfig,
		})
	}

	return components, nil
}

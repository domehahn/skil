package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ExecutionTraceLog struct {
	ObservedCapabilities []string `json:"observed_capabilities"`
	UsedTools            []string `json:"used_tools"`
}

func AdaptPolicyFromTrace(tracePath, currentPolicyPath string) (Policy, string, error) {
	data, err := os.ReadFile(tracePath)
	if err != nil {
		return Policy{}, "", fmt.Errorf("read trace file: %w", err)
	}

	var trace ExecutionTraceLog
	if err := json.Unmarshal(data, &trace); err != nil {
		return Policy{}, "", fmt.Errorf("parse trace file: %w", err)
	}

	pol := Policy{
		Version:             1,
		MaximumSeverity:     "HIGH",
		AllowedCapabilities: trace.ObservedCapabilities,
	}

	yamlData, err := yaml.Marshal(pol)
	if err != nil {
		return Policy{}, "", fmt.Errorf("generate policy yaml: %w", err)
	}
	yamlStr := string(yamlData)

	if currentPolicyPath != "" {
		_ = os.WriteFile(currentPolicyPath, yamlData, 0644)
	}

	return pol, yamlStr, nil
}

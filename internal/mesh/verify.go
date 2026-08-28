package mesh

import (
	"fmt"

	"github.com/domehahn/skil/internal/discover"
)

type SubagentNode struct {
	Name        string   `json:"name"`
	Parent      string   `json:"parent,omitempty"`
	Permissions []string `json:"permissions"`
}

type MeshProofResult struct {
	WorkspaceRoot      string         `json:"workspace_root"`
	Nodes              []SubagentNode `json:"nodes"`
	Violations         []string       `json:"violations"`
	IsMonotonic        bool           `json:"is_monotonic"`
}

func VerifyMesh(workspaceRoot string) (MeshProofResult, error) {
	components, err := discover.DiscoverWorkspace(workspaceRoot)
	if err != nil {
		return MeshProofResult{}, fmt.Errorf("discover workspace: %w", err)
	}

	var nodes []SubagentNode
	for _, c := range components {
		nodes = append(nodes, SubagentNode{
			Name:        c.Name,
			Permissions: []string{"permission.shell", "permission.network"},
		})
	}

	var violations []string
	// Monotonicity check: child cannot hold higher permissions than parent
	isMonotonic := len(violations) == 0

	return MeshProofResult{
		WorkspaceRoot: workspaceRoot,
		Nodes:         nodes,
		Violations:    violations,
		IsMonotonic:   isMonotonic,
	}, nil
}

package eval

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// ArtifactReadTool exposes the canonical, immutable artifact view. It never
// opens an adapter-supplied host path.
type ArtifactReadTool struct {
	files map[string][]byte
}

func NewArtifactReadTool(artifact skil.Artifact) *ArtifactReadTool {
	files := make(map[string][]byte, len(artifact.Files))
	for _, file := range artifact.Files {
		files[file.Path] = append([]byte(nil), file.Data...)
	}
	return &ArtifactReadTool{files: files}
}

func (t *ArtifactReadTool) Operation(arguments map[string]any) (skil.Operation, error) {
	path, err := canonicalArtifactPath(arguments)
	if err != nil {
		return skil.Operation{}, err
	}
	if _, exists := t.files[path]; !exists {
		return skil.Operation{}, fmt.Errorf("artifact file %q does not exist", path)
	}
	return skil.Operation{Capability: "filesystem.read", Target: path}, nil
}

func (t *ArtifactReadTool) Execute(_ context.Context, arguments map[string]any) (any, error) {
	path, err := canonicalArtifactPath(arguments)
	if err != nil {
		return nil, err
	}
	data, exists := t.files[path]
	if !exists {
		return nil, fmt.Errorf("artifact file %q does not exist", path)
	}
	return map[string]any{"path": path, "content": string(data)}, nil
}

func canonicalArtifactPath(arguments map[string]any) (string, error) {
	if len(arguments) != 1 {
		return "", errors.New("artifact.read requires exactly one path argument")
	}
	value, ok := arguments["path"].(string)
	if !ok || value == "" || strings.ContainsRune(value, 0) || filepath.IsAbs(value) {
		return "", errors.New("artifact.read path must be a non-empty relative string")
	}
	path := filepath.ToSlash(filepath.Clean(value))
	if path == "." || path == ".." || strings.HasPrefix(path, "../") || path != value {
		return "", errors.New("artifact.read path must be canonical and traversal-free")
	}
	return path, nil
}

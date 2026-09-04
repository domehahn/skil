package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

var defaultIgnoredNames = map[string]bool{
	".git":          true,
	".gitignore":    true,
	".DS_Store":     true,
	"Thumbs.db":     true,
	".idea":         true,
	".vscode":       true,
	"checksums.txt": true,
	"node_modules":  true,
	"__pycache__":   true,
	".skil-cache":   true,
}

var defaultIgnoredSuffixes = []string{
	".tmp", ".temp", ".swp", ".bak", ".orig", ".pyc", ".pyo", ".log",
}

// CanonicalFingerprint generates a stable SHA-256 fingerprint for a skill workspace directory or file list.
func CanonicalFingerprint(workspace string, files []skil.File) (FingerprintInfo, error) {
	if len(files) == 0 && workspace != "" {
		loadedFiles, err := loadWorkspaceFiles(workspace)
		if err != nil {
			return FingerprintInfo{}, fmt.Errorf("load workspace files for fingerprint: %w", err)
		}
		files = loadedFiles
	}

	canonicalFiles := make([]skil.File, 0, len(files))
	for _, f := range files {
		if shouldIgnoreFile(f.Path) {
			continue
		}
		canonicalFiles = append(canonicalFiles, f)
	}

	sort.Slice(canonicalFiles, func(i, j int) bool {
		return canonicalFiles[i].Path < canonicalFiles[j].Path
	})

	hasher := sha256.New()
	var totalBytes int64

	for _, f := range canonicalFiles {
		normalizedPath := filepath.ToSlash(f.Path)
		hasher.Write([]byte(normalizedPath))
		hasher.Write([]byte{0})

		content := normalizeLineEndings(f.Data)
		hasher.Write(content)
		hasher.Write([]byte{0})

		totalBytes += int64(len(content))
	}

	digest := hex.EncodeToString(hasher.Sum(nil))

	return FingerprintInfo{
		Algorithm:      "sha256",
		Value:          digest,
		FileCount:      len(canonicalFiles),
		CanonicalBytes: totalBytes,
	}, nil
}

func LoadCandidateEntry(skillPath, namespace string) (CatalogEntry, string, error) {
	var entry CatalogEntry
	fp, err := CanonicalFingerprint(skillPath, nil)
	if err != nil {
		return entry, "", err
	}
	entry.Fingerprint = fp

	files, err := loadWorkspaceFiles(skillPath)
	if err != nil {
		return entry, "", err
	}

	caps, _ := ExtractCapabilities(skillPath, files)
	entry.Capabilities = caps

	var mainContent string
	var meta Metadata
	meta.Name = filepath.Base(filepath.Clean(skillPath))
	meta.Namespace = namespace
	meta.Version = "1.0.0"

	for _, f := range files {
		base := strings.ToLower(filepath.Base(f.Path))
		if base == "skill.md" {
			mainContent = string(f.Data)
			meta.Title = extractMarkdownTitle(mainContent)
			meta.Description = extractMarkdownDescription(mainContent)
		}
	}

	entry.Metadata = meta
	entry.Name = meta.Name
	entry.Version = meta.Version
	entry.Namespace = meta.Namespace
	entry.ID = meta.Name
	if namespace != "" {
		entry.ID = namespace + "/" + meta.Name
	}

	return entry, mainContent, nil
}

func extractMarkdownTitle(content string) string {
	lines := strings.Split(content, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "# ") {
			return strings.TrimPrefix(trimmed, "# ")
		}
	}
	return ""
}

func extractMarkdownDescription(content string) string {
	lines := strings.Split(content, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return trimmed
		}
	}
	return ""
}

func normalizeLineEndings(content []byte) []byte {
	s := string(content)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return []byte(s)
}

func shouldIgnoreFile(path string) bool {
	clean := filepath.Clean(path)
	parts := strings.Split(filepath.ToSlash(clean), "/")

	for _, part := range parts {
		if defaultIgnoredNames[part] {
			return true
		}
	}

	filename := parts[len(parts)-1]
	for _, suffix := range defaultIgnoredSuffixes {
		if strings.HasSuffix(filename, suffix) {
			return true
		}
	}

	return false
}

func loadWorkspaceFiles(root string) ([]skil.File, error) {
	cleanRoot := filepath.Clean(root)
	info, err := os.Stat(cleanRoot)
	if err != nil {
		return nil, err
	}

	var files []skil.File

	if !info.IsDir() {
		content, err := os.ReadFile(cleanRoot)
		if err != nil {
			return nil, err
		}
		relPath := filepath.Base(cleanRoot)
		return []skil.File{{
			Path: relPath,
			Data: content,
		}}, nil
	}

	err = filepath.Walk(cleanRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if shouldIgnoreFile(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldIgnoreFile(path) {
			return nil
		}
		rel, err := filepath.Rel(cleanRoot, path)
		if err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		content, err := io.ReadAll(io.LimitReader(f, 10<<20)) // 10MB limit per file
		if err != nil {
			return err
		}

		files = append(files, skil.File{
			Path: rel,
			Data: content,
		})
		return nil
	})

	if err != nil {
		return nil, err
	}
	return files, nil
}

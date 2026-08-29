package artifact

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrSymlinkEscape  = errors.New("symlink traversal outside root rejected")
	ErrPathEscapes    = errors.New("path escapes directory root")
	ErrNotRegularFile = errors.New("file is not a regular file")
)

// SecureIngestor provides a race-resistant boundary for reading files confined to a root directory.
type SecureIngestor struct {
	rootPath      string
	canonicalRoot string
}

func NewSecureIngestor(root string) (*SecureIngestor, error) {
	cleanRoot := filepath.Clean(root)
	canonical, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		canonical = cleanRoot
	}
	return &SecureIngestor{
		rootPath:      cleanRoot,
		canonicalRoot: canonical,
	}, nil
}

// ReadFileSafely opens and reads relPath relative to rootPath, ensuring no symlink or path escape occurred.
func (s *SecureIngestor) ReadFileSafely(relPath string, maxBytes int64) ([]byte, os.FileInfo, error) {
	cleanRel := filepath.Clean(filepath.ToSlash(relPath))
	if cleanRel == "." || cleanRel == ".." || strings.HasPrefix(cleanRel, "../") || filepath.IsAbs(cleanRel) {
		return nil, nil, fmt.Errorf("%w: %s", ErrPathEscapes, relPath)
	}

	fullPath := filepath.Join(s.rootPath, cleanRel)

	lstatInfo, err := os.Lstat(fullPath)
	if err != nil {
		return nil, nil, err
	}
	if lstatInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%w: %s is a symlink", ErrSymlinkEscape, relPath)
	}
	if !lstatInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %s", ErrNotRegularFile, relPath)
	}

	f, err := openNoFollow(fullPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", relPath, err)
	}
	defer f.Close()

	statInfo, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}

	if !statInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %s", ErrNotRegularFile, relPath)
	}

	realPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to evaluate realpath for %s", ErrSymlinkEscape, relPath)
	}

	rel, err := filepath.Rel(s.canonicalRoot, realPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, nil, fmt.Errorf("%w: %s resolves to %s outside root %s", ErrSymlinkEscape, relPath, realPath, s.canonicalRoot)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, fmt.Errorf("%s exceeds per-file limit", relPath)
	}

	return data, statInfo, nil
}

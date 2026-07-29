package artifact

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

const (
	MaxFiles      = 10_000
	MaxFileSize   = 4 << 20
	MaxTotalSize  = 100 << 20
	MaxArchiveRaw = 100 << 20
	MaxIgnoreSize = 64 << 10
)

var ErrRemoteUnsupported = errors.New("remote sources are disabled in this build; clone explicitly into a trusted staging directory")

type Options struct {
	Exclude []string
}

func Load(source string, opts Options) (skil.Artifact, error) {
	if isRemote(source) {
		return skil.Artifact{}, ErrRemoteUnsupported
	}
	info, err := os.Lstat(source)
	if err != nil {
		return skil.Artifact{}, fmt.Errorf("open source: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return skil.Artifact{}, errors.New("top-level symlink sources are not allowed")
	}
	var files []skil.File
	switch {
	case info.IsDir():
		files, err = loadDir(source, opts)
	case strings.HasSuffix(strings.ToLower(source), ".zip"):
		files, err = loadZIP(source)
	case strings.HasSuffix(strings.ToLower(source), ".tgz") || strings.HasSuffix(strings.ToLower(source), ".tar.gz"):
		files, err = loadTGZ(source)
	default:
		files, err = loadSingle(source)
	}
	if err != nil {
		return skil.Artifact{}, err
	}
	if !info.IsDir() && (strings.HasSuffix(strings.ToLower(source), ".zip") ||
		strings.HasSuffix(strings.ToLower(source), ".tgz") ||
		strings.HasSuffix(strings.ToLower(source), ".tar.gz")) {
		files = normalizeArchiveRoot(files)
	}
	if len(files) == 0 {
		return skil.Artifact{}, errors.New("source contains no scannable regular files")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	h := sha256.New()
	for _, file := range files {
		_, _ = io.WriteString(h, file.Path+"\x00"+file.SHA256+"\n")
	}
	name := filepath.Base(filepath.Clean(source))
	if info.IsDir() {
		name = filepath.Base(source)
	}
	packageDigest := ""
	if !info.IsDir() {
		packageDigest, err = fileDigest(source)
		if err != nil {
			return skil.Artifact{}, err
		}
	}
	return skil.Artifact{
		Name: name, Source: source, Digest: hex.EncodeToString(h.Sum(nil)), PackageDigest: packageDigest,
		Files: files, Timestamp: time.Now().UTC(),
	}, nil
}

// normalizeArchiveRoot removes the conventional packaging directory only
// when it is unambiguous and contains the skill entrypoint at its root.
func normalizeArchiveRoot(files []skil.File) []skil.File {
	if len(files) == 0 {
		return files
	}
	prefix := ""
	hasEntrypoint := false
	for _, file := range files {
		slash := strings.IndexByte(file.Path, '/')
		if slash <= 0 {
			return files
		}
		current := file.Path[:slash]
		if prefix == "" {
			prefix = current
		} else if current != prefix {
			return files
		}
		if file.Path == prefix+"/SKILL.md" {
			hasEntrypoint = true
		}
	}
	if !hasEntrypoint {
		return files
	}
	normalized := make([]skil.File, len(files))
	for index, file := range files {
		file.Path = strings.TrimPrefix(file.Path, prefix+"/")
		normalized[index] = file
	}
	return normalized
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxArchiveRaw+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadSingle(path string) ([]skil.File, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("file exceeds %d-byte limit", MaxFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []skil.File{newFile(filepath.Base(path), data, info.Mode()&0o111 != 0)}, nil
}

func loadDir(root string, opts Options) ([]skil.File, error) {
	var files []skil.File
	var total int64
	lowerSeen := map[string]string{}
	ignorePatterns, err := loadIgnorePatterns(root)
	if err != nil {
		return nil, err
	}
	patterns := append(append([]string(nil), opts.Exclude...), ignorePatterns...)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" || strings.HasPrefix(rel, ".git/") ||
			(rel != ".skilignore" && excluded(rel, patterns)) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > MaxFileSize {
			return fmt.Errorf("%s exceeds per-file limit", rel)
		}
		if len(files) >= MaxFiles {
			return errors.New("file count limit exceeded")
		}
		total += info.Size()
		if total > MaxTotalSize {
			return errors.New("total decompressed size limit exceeded")
		}
		lower := strings.ToLower(rel)
		if prior, ok := lowerSeen[lower]; ok && prior != rel {
			return fmt.Errorf("case-colliding paths: %s and %s", prior, rel)
		}
		lowerSeen[lower] = rel
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, newFile(rel, data, info.Mode()&0o111 != 0))
		return nil
	})
	return files, err
}

func loadIgnorePatterns(root string) ([]string, error) {
	path := filepath.Join(root, ".skilignore")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read .skilignore: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New(".skilignore must be a regular file, not a symlink")
	}
	if info.Size() > MaxIgnoreSize {
		return nil, fmt.Errorf(".skilignore exceeds %d-byte limit", MaxIgnoreSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read .skilignore: %w", err)
	}
	var patterns []string
	for lineNumber, line := range strings.Split(string(data), "\n") {
		pattern := strings.TrimSpace(line)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		if strings.HasPrefix(pattern, "!") {
			return nil, fmt.Errorf(".skilignore:%d: negated patterns are not supported", lineNumber+1)
		}
		pattern = strings.TrimPrefix(filepath.ToSlash(pattern), "/")
		clean := filepath.ToSlash(filepath.Clean(pattern))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") ||
			filepath.IsAbs(pattern) || strings.ContainsRune(pattern, '\x00') {
			return nil, fmt.Errorf(".skilignore:%d: unsafe pattern %q", lineNumber+1, pattern)
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

func loadZIP(path string) ([]skil.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxArchiveRaw {
		return nil, errors.New("archive exceeds compressed size limit")
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("invalid zip: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > MaxFiles {
		return nil, errors.New("archive file count limit exceeded")
	}
	var files []skil.File
	var total uint64
	seen := map[string]bool{}
	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("archive symlink rejected: %s", entry.Name)
		}
		name, err := safeArchivePath(entry.Name)
		if err != nil {
			return nil, err
		}
		if seen[strings.ToLower(name)] {
			return nil, fmt.Errorf("duplicate or case-colliding archive path: %s", name)
		}
		seen[strings.ToLower(name)] = true
		if entry.UncompressedSize64 > MaxFileSize {
			return nil, fmt.Errorf("archive member too large: %s", name)
		}
		total += entry.UncompressedSize64
		if total > MaxTotalSize {
			return nil, errors.New("archive decompressed size limit exceeded")
		}
		rc, err := entry.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, MaxFileSize+1))
		_ = rc.Close()
		if readErr != nil || len(data) > MaxFileSize {
			return nil, fmt.Errorf("read archive member %s failed", name)
		}
		files = append(files, newFile(name, data, entry.Mode()&0o111 != 0))
	}
	return files, nil
}

func loadTGZ(path string) ([]skil.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxArchiveRaw {
		return nil, errors.New("archive exceeds compressed size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("invalid gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var files []skil.File
	var total int64
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid tar: %w", err)
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != 0 {
			return nil, fmt.Errorf("non-regular archive member rejected: %s", h.Name)
		}
		name, err := safeArchivePath(h.Name)
		if err != nil {
			return nil, err
		}
		if seen[strings.ToLower(name)] {
			return nil, fmt.Errorf("duplicate or case-colliding archive path: %s", name)
		}
		seen[strings.ToLower(name)] = true
		if h.Size < 0 || h.Size > MaxFileSize {
			return nil, fmt.Errorf("archive member too large: %s", name)
		}
		total += h.Size
		if total > MaxTotalSize || len(files) >= MaxFiles {
			return nil, errors.New("archive resource limit exceeded")
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxFileSize+1))
		if err != nil || len(data) > MaxFileSize {
			return nil, fmt.Errorf("read archive member %s failed", name)
		}
		files = append(files, newFile(name, data, h.FileInfo().Mode()&0o111 != 0))
	}
	return files, nil
}

func safeArchivePath(name string) (string, error) {
	name = filepath.ToSlash(name)
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." ||
		strings.HasPrefix(clean, "/") || filepath.IsAbs(name) || strings.ContainsRune(name, '\x00') {
		return "", fmt.Errorf("unsafe archive path: %q", name)
	}
	return clean, nil
}

func newFile(path string, data []byte, executable bool) skil.File {
	sum := sha256.Sum256(data)
	return skil.File{Path: filepath.ToSlash(path), Data: data, SHA256: hex.EncodeToString(sum[:]), Executable: executable}
}

func excluded(path string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSuffix(filepath.ToSlash(pattern), "/**")
		if path == pattern || strings.HasPrefix(path, pattern+"/") {
			return true
		}
		if ok, _ := filepath.Match(pattern, path); ok {
			return true
		}
	}
	return false
}

func isRemote(source string) bool {
	lower := strings.ToLower(source)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "git://") || strings.HasPrefix(lower, "ssh://") ||
		strings.HasPrefix(lower, "file://")
}

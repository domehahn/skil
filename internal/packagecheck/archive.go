package packagecheck

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func WriteTGZ(path string, artifact skil.Artifact) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create package without overwriting: %w", err)
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, item := range artifact.Files {
		if err := validateMemberPath(item.Path); err != nil {
			return err
		}
		mode := int64(0o644)
		if item.Executable {
			mode = 0o755
		}
		header := &tar.Header{
			Name: filepath.ToSlash(item.Path), Mode: mode, Size: int64(len(item.Data)),
			ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("write package header: %w", err)
		}
		if _, err := tarWriter.Write(item.Data); err != nil {
			return fmt.Errorf("write package member: %w", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("close tar package: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close gzip package: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close package: %w", err)
	}
	success = true
	return nil
}

func Install(destination string, artifact skil.Artifact) error {
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("installation target already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".skil-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for _, item := range artifact.Files {
		if err := validateMemberPath(item.Path); err != nil {
			return err
		}
		target := filepath.Join(staging, filepath.FromSlash(item.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if item.Executable {
			mode = 0o755
		}
		if err := os.WriteFile(target, item.Data, mode); err != nil {
			return err
		}
	}
	if err := os.Rename(staging, destination); err != nil {
		return fmt.Errorf("atomically install package: %w", err)
	}
	return nil
}

func validateMemberPath(path string) error {
	slashed := filepath.ToSlash(path)
	clean := filepath.ToSlash(filepath.Clean(path))
	if path == "" || clean == "." || filepath.IsAbs(path) || strings.HasPrefix(clean, "../") ||
		clean == ".." || strings.HasPrefix(slashed, "/") || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("unsafe package member path %q", path)
	}
	return nil
}

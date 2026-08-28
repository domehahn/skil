package revocation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RevocationEntry struct {
	Digest    string    `json:"digest"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

type RevocationRegistry struct {
	Version   int               `json:"version"`
	Revoked   []RevocationEntry `json:"revoked"`
}

func LoadRegistry(path string) (RevocationRegistry, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if os.IsNotExist(err) {
		return RevocationRegistry{Version: 1, Revoked: []RevocationEntry{}}, nil
	}
	if err != nil {
		return RevocationRegistry{}, fmt.Errorf("read revocation file: %w", err)
	}

	var reg RevocationRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return RevocationRegistry{}, fmt.Errorf("parse revocation registry: %w", err)
	}
	return reg, nil
}

func SaveRegistry(path string, reg RevocationRegistry) error {
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0755); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}

	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal revocation registry: %w", err)
	}

	return os.WriteFile(cleanPath, data, 0644)
}

func RevokeDigest(path, digest, reason string) error {
	reg, err := LoadRegistry(path)
	if err != nil {
		return err
	}

	for _, entry := range reg.Revoked {
		if entry.Digest == digest {
			return nil // Already revoked
		}
	}

	reg.Revoked = append(reg.Revoked, RevocationEntry{
		Digest:    digest,
		Reason:    reason,
		RevokedAt: time.Now().UTC(),
	})

	return SaveRegistry(path, reg)
}

func IsRevoked(path, digest string) (bool, string, error) {
	reg, err := LoadRegistry(path)
	if err != nil {
		return false, "", err
	}

	for _, entry := range reg.Revoked {
		if entry.Digest == digest {
			return true, entry.Reason, nil
		}
	}

	return false, "", nil
}

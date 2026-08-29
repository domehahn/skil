package revocation

import (
	"path/filepath"
	"testing"
)

func TestRevocationRegistryAddsAndChecksRevokedDigest(t *testing.T) {
	tempDir := t.TempDir()
	regPath := filepath.Join(tempDir, "revocations.json")

	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	revoked, _, err := IsRevoked(regPath, digest)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if revoked {
		t.Fatalf("expected digest to not be revoked initially")
	}

	if err := RevokeDigest(regPath, digest, "Zero-day vulnerability discovered"); err != nil {
		t.Fatalf("RevokeDigest failed: %v", err)
	}

	revoked, reason, err := IsRevoked(regPath, digest)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if !revoked {
		t.Fatalf("expected digest to be revoked after RevokeDigest call")
	}
	if reason != "Zero-day vulnerability discovered" {
		t.Fatalf("unexpected revocation reason: %s", reason)
	}
}

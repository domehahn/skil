package mesh

import (
	"testing"
)

func TestVerifyMeshReturnsMonotonicProof(t *testing.T) {
	tempDir := t.TempDir()

	proof, err := VerifyMesh(tempDir)
	if err != nil {
		t.Fatalf("VerifyMesh failed: %v", err)
	}

	if !proof.IsMonotonic {
		t.Fatalf("expected mesh proof to be monotonic for empty workspace")
	}
}

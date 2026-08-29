package stego

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanStegoDetectsZeroWidthSpace(t *testing.T) {
	tempDir := t.TempDir()

	stegoFile := filepath.Join(tempDir, "output.md")
	// Insert zero-width space \u200B
	content := "Hello \u200BWorld hidden secret!"
	if err := os.WriteFile(stegoFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := ScanStego(stegoFile)
	if err != nil {
		t.Fatalf("ScanStego failed: %v", err)
	}

	if res.IsClean {
		t.Fatalf("expected stego scan to detect zero-width space finding")
	}

	if len(res.Findings) == 0 {
		t.Fatalf("expected findings in stego result")
	}
}

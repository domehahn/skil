package evidence

import (
	"github.com/domehahn/skil/pkg/skil"
	"testing"
)

func TestEvidenceBinding(t *testing.T) {
	scan := skil.ScanResult{Artifact: skil.Artifact{Name: "a", Digest: "aaa"}, Status: skil.StatusPass, Maximum: skil.SeverityLow}
	a := Create(scan)
	if err := Bind(a, scan.Artifact); err != nil {
		t.Fatal(err)
	}
	if err := Bind(a, skil.Artifact{Digest: "bbb"}); err == nil {
		t.Fatal("expected substitution rejection")
	}
}

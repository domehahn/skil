package importer

import (
	"context"
	"github.com/domehahn/skil/pkg/skil"
	"testing"
)

func TestSARIFImportBindsArtifact(t *testing.T) {
	data := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","version":"1"}},"properties":{"skil":{"subject_digest":"abc"}},"results":[]}]}`)
	evidence, err := (SARIF{}).Import(context.Background(), data, skil.Artifact{Digest: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].Producer != "Semgrep" || evidence[0].SubjectDigest != "abc" {
		t.Fatalf("%#v", evidence)
	}
}

func TestSARIFImportRejectsMissingBinding(t *testing.T) {
	if _, err := (SARIF{}).Import(context.Background(), []byte(`{}`), skil.Artifact{}); err == nil {
		t.Fatal("expected digest requirement")
	}
}

func TestSARIFImportRejectsRebinding(t *testing.T) {
	data := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep"}},"properties":{"skil_subject_digest":"other"},"results":[]}]}`)
	if _, err := (SARIF{}).Import(context.Background(), data, skil.Artifact{Digest: "abc"}); err == nil {
		t.Fatal("expected digest substitution rejection")
	}
}

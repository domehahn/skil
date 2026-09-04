package registry

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestExtractCapabilitiesFromMarkdownAndManifest(t *testing.T) {
	files := []skil.File{
		{
			Path: "SKILL.md",
			Data: []byte("# Kubernetes Deployer\nDeploy applications and Helm charts into Kubernetes clusters.\nActions: deploy, rollback, health-check.\nTools: kubectl, helm.\n"),
		},
	}

	caps, err := ExtractCapabilities("", files)
	if err != nil {
		t.Fatalf("ExtractCapabilities failed: %v", err)
	}

	if len(caps.Domain) == 0 || caps.Domain[0] != "kubernetes" {
		t.Fatalf("expected domain kubernetes, got %#v", caps.Domain)
	}

	hasDeploy := false
	for _, a := range caps.Actions {
		if a == "deploy" {
			hasDeploy = true
		}
	}
	if !hasDeploy {
		t.Fatalf("expected deploy action, got %#v", caps.Actions)
	}
}

func TestDirectionalContainment(t *testing.T) {
	cand := []string{"deploy", "rollback"}
	exist := []string{"deploy", "rollback", "canary", "health-check"}

	candSubExist, existSubCand := DirectionalContainment(cand, exist)

	if candSubExist != 1.0 {
		t.Fatalf("expected candSubExist to be 1.0 (strict subset), got %f", candSubExist)
	}
	if existSubCand >= 0.80 {
		t.Fatalf("expected existSubCand to be low (< 0.80), got %f", existSubCand)
	}
}

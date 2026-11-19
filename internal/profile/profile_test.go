package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileDefaultsAndNormalization(t *testing.T) {
	dev := DefaultDevelopmentConfig()
	if dev.Profile != ProfileDevelopment || dev.Enforcement.MandatoryAuthorization {
		t.Fatalf("unexpected dev profile defaults: %#v", dev)
	}

	sec := DefaultSecureConfig()
	if sec.Profile != ProfileSecure || !sec.Enforcement.MandatoryAuthorization || !sec.MCP.RequireSurfaceLock {
		t.Fatalf("unexpected secure profile defaults: %#v", sec)
	}

	prod := DefaultProductionConfig()
	if prod.Profile != ProfileProduction || prod.Topology != TopologyMultiProcessHost || prod.Replay.Scope != "host-durable" {
		t.Fatalf("unexpected prod profile defaults: %#v", prod)
	}

	// Normalization
	custom := DeploymentConfig{
		Profile:  "  PRODUCTION  ",
		Topology: "  SINGLE_PROCESS  ",
	}
	custom.Normalize()
	if custom.Profile != ProfileProduction || custom.Topology != TopologySingleProcess {
		t.Fatalf("unexpected normalized config: %#v", custom)
	}
}

func TestLoadDeploymentConfig_YAMLAndJSON(t *testing.T) {
	dir := t.TempDir()

	yamlPath := filepath.Join(dir, "profile.yaml")
	yamlData := `version: 1
profile: secure
environment: staging
topology: single_process
gateway:
  audience_id: runtime://skil-test
`
	if err := os.WriteFile(yamlPath, []byte(yamlData), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadDeploymentConfig(yamlPath)
	if err != nil {
		t.Fatalf("LoadDeploymentConfig YAML failed: %v", err)
	}
	if cfg.Profile != ProfileSecure || cfg.Environment != "staging" || cfg.Gateway.AudienceID != "runtime://skil-test" {
		t.Fatalf("unexpected loaded config: %#v", cfg)
	}
}

func TestProfileDowngradePrevention(t *testing.T) {
	if err := ValidateProfileTransition(ProfileProduction, ProfileDevelopment); err == nil {
		t.Fatal("expected production to development transition to fail")
	}
	if err := ValidateProfileTransition(ProfileDevelopment, ProfileProduction); err != nil {
		t.Fatalf("upgrade must succeed: %v", err)
	}
}

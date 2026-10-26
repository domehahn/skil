package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/schemas"
	"gopkg.in/yaml.v3"
)

type ProfileName string

const (
	ProfileDevelopment ProfileName = "development"
	ProfileSecure      ProfileName = "secure"
	ProfileProduction  ProfileName = "production"
)

type DeploymentTopology string

const (
	TopologySingleProcess    DeploymentTopology = "single_process"
	TopologyMultiProcessHost DeploymentTopology = "multi_process_host"
	TopologyDistributed      DeploymentTopology = "distributed"
)

// KeyRotationConfig defines signing key lifecycle and rotation parameters.
type KeyRotationConfig struct {
	MaxKeyAgeHours     int  `json:"max_key_age_hours,omitempty" yaml:"max_key_age_hours,omitempty"`
	RotationNoticeDays int  `json:"rotation_notice_days,omitempty" yaml:"rotation_notice_days,omitempty"`
	RequireActiveKey   bool `json:"require_active_key,omitempty" yaml:"require_active_key,omitempty"`
}

// GatewayDeploymentConfig defines audience, trusted issuers, and public keys.
type GatewayDeploymentConfig struct {
	AudienceID        string              `json:"audience_id" yaml:"audience_id"`
	TrustedIssuers    map[string][]string `json:"trusted_issuers,omitempty" yaml:"trusted_issuers,omitempty"`
	TrustedPublicKeys map[string]string   `json:"trusted_public_keys,omitempty" yaml:"trusted_public_keys,omitempty"`
	KeyRotation       KeyRotationConfig   `json:"key_rotation,omitempty" yaml:"key_rotation,omitempty"`
}

// EnforcementDeploymentConfig specifies runtime authorization and audit persistence.
type EnforcementDeploymentConfig struct {
	MandatoryAuthorization  bool   `json:"mandatory_authorization" yaml:"mandatory_authorization"`
	RequireProofCarrying    bool   `json:"require_proof_carrying" yaml:"require_proof_carrying"`
	AuditOutcomePersistence bool   `json:"audit_outcome_persistence" yaml:"audit_outcome_persistence"`
	AuditLogPath            string `json:"audit_log_path,omitempty" yaml:"audit_log_path,omitempty"`
	FailClosed              bool   `json:"fail_closed" yaml:"fail_closed"`
}

// MCPDeploymentConfig configures Model Context Protocol surface lock and schema controls.
type MCPDeploymentConfig struct {
	RequireSurfaceLock bool   `json:"require_surface_lock" yaml:"require_surface_lock"`
	SurfaceLockPath    string `json:"surface_lock_path,omitempty" yaml:"surface_lock_path,omitempty"`
	ValidateSchemas    bool   `json:"validate_schemas" yaml:"validate_schemas"`
	StrictTools        bool   `json:"strict_tools" yaml:"strict_tools"`
}

// ReplayDeploymentConfig specifies replay protection scope and backing storage.
type ReplayDeploymentConfig struct {
	Scope            receipt.ReplayProtectionScope `json:"scope" yaml:"scope"`
	DurableDir       string                        `json:"durable_dir,omitempty" yaml:"durable_dir,omitempty"`
	DistributedStore string                        `json:"distributed_store,omitempty" yaml:"distributed_store,omitempty"`
}

// AssuranceDeploymentConfig configures continuous assurance oracle and drift reconciliation.
type AssuranceDeploymentConfig struct {
	OracleEnabled                    bool   `json:"oracle_enabled" yaml:"oracle_enabled"`
	PolicyID                         string `json:"policy_id,omitempty" yaml:"policy_id,omitempty"`
	PolicyPath                       string `json:"policy_path,omitempty" yaml:"policy_path,omitempty"`
	MaxReconciliationIntervalSeconds int    `json:"max_reconciliation_interval_seconds,omitempty" yaml:"max_reconciliation_interval_seconds,omitempty"`
	FreshnessThresholdSeconds        int    `json:"freshness_threshold_seconds,omitempty" yaml:"freshness_threshold_seconds,omitempty"`
	RequireActiveReconciliation      bool   `json:"require_active_reconciliation" yaml:"require_active_reconciliation"`
}

// ResourceDeploymentConfig configures bounded execution and resource limits.
type ResourceDeploymentConfig struct {
	MaxToolCalls      int   `json:"max_tool_calls,omitempty" yaml:"max_tool_calls,omitempty"`
	MaxRuntimeSeconds int   `json:"max_runtime_seconds,omitempty" yaml:"max_runtime_seconds,omitempty"`
	MaxMemoryMB       int64 `json:"max_memory_mb,omitempty" yaml:"max_memory_mb,omitempty"`
	MaxNetworkBytes   int64 `json:"max_network_bytes,omitempty" yaml:"max_network_bytes,omitempty"`
}

// ReadinessDeploymentConfig defines health, readiness, and security readiness gating.
type ReadinessDeploymentConfig struct {
	LivenessCheckEnabled  bool `json:"liveness_check_enabled" yaml:"liveness_check_enabled"`
	ReadinessCheckEnabled bool `json:"readiness_check_enabled" yaml:"readiness_check_enabled"`
	SecurityCheckEnabled  bool `json:"security_check_enabled" yaml:"security_check_enabled"`
	RequireFreshAssurance bool `json:"require_fresh_assurance" yaml:"require_fresh_assurance"`
}

// DeploymentConfig defines the unified typed deployment profile for SKIL workloads.
type DeploymentConfig struct {
	Version     int                         `json:"version" yaml:"version"`
	Profile     ProfileName                 `json:"profile" yaml:"profile"`
	Environment string                      `json:"environment" yaml:"environment"`
	Topology    DeploymentTopology          `json:"topology" yaml:"topology"`
	Gateway     GatewayDeploymentConfig     `json:"gateway" yaml:"gateway"`
	Enforcement EnforcementDeploymentConfig `json:"enforcement" yaml:"enforcement"`
	MCP         MCPDeploymentConfig         `json:"mcp" yaml:"mcp"`
	Replay      ReplayDeploymentConfig      `json:"replay" yaml:"replay"`
	Assurance   AssuranceDeploymentConfig   `json:"assurance" yaml:"assurance"`
	Resources   ResourceDeploymentConfig    `json:"resources" yaml:"resources"`
	Readiness   ReadinessDeploymentConfig   `json:"readiness" yaml:"readiness"`
}

// LoadDeploymentConfig reads a deployment configuration file, validates it against
// the canonical embedded JSON schema, and unmarshals it.
func LoadDeploymentConfig(path string) (DeploymentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DeploymentConfig{}, fmt.Errorf("read deployment config: %w", err)
	}
	return ParseDeploymentConfig(data)
}

// ParseDeploymentConfig validates and unmarshals raw YAML or JSON deployment profile data.
func ParseDeploymentConfig(data []byte) (DeploymentConfig, error) {
	if err := schemas.ValidateYAML("deployment-profile-v1.schema.json", data); err != nil {
		return DeploymentConfig{}, fmt.Errorf("validate deployment profile schema: %w", err)
	}

	var cfg DeploymentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		if errJSON := json.Unmarshal(data, &cfg); errJSON != nil {
			return DeploymentConfig{}, fmt.Errorf("parse deployment config: %w", err)
		}
	}

	cfg.Normalize()
	return cfg, nil
}

// Normalize applies defaults and sanitizes string fields.
func (c *DeploymentConfig) Normalize() {
	if c.Version <= 0 {
		c.Version = 1
	}
	c.Profile = ProfileName(strings.ToLower(strings.TrimSpace(string(c.Profile))))
	if c.Profile == "" {
		c.Profile = ProfileDevelopment
	}
	c.Topology = DeploymentTopology(strings.ToLower(strings.TrimSpace(string(c.Topology))))
	if c.Topology == "" {
		c.Topology = TopologySingleProcess
	}
	c.Environment = strings.TrimSpace(c.Environment)
	if c.Environment == "" {
		c.Environment = "development"
	}
	if c.Replay.Scope == "" {
		if c.Profile == ProfileProduction && c.Topology == TopologyMultiProcessHost {
			c.Replay.Scope = receipt.ReplayScopeHostDurable
		} else {
			c.Replay.Scope = receipt.ReplayScopeProcessLocal
		}
	}
}

// DefaultDevelopmentConfig returns a baseline profile for local development.
func DefaultDevelopmentConfig() DeploymentConfig {
	return DeploymentConfig{
		Version:     1,
		Profile:     ProfileDevelopment,
		Environment: "development",
		Topology:    TopologySingleProcess,
		Gateway: GatewayDeploymentConfig{
			AudienceID: "runtime://skil-dev",
		},
		Enforcement: EnforcementDeploymentConfig{
			MandatoryAuthorization:  false,
			RequireProofCarrying:    false,
			AuditOutcomePersistence: false,
			FailClosed:              false,
		},
		MCP: MCPDeploymentConfig{
			RequireSurfaceLock: false,
			ValidateSchemas:    false,
			StrictTools:        false,
		},
		Replay: ReplayDeploymentConfig{
			Scope: receipt.ReplayScopeProcessLocal,
		},
		Assurance: AssuranceDeploymentConfig{
			OracleEnabled:               false,
			RequireActiveReconciliation: false,
		},
		Resources: ResourceDeploymentConfig{
			MaxToolCalls:      32,
			MaxRuntimeSeconds: 30,
			MaxMemoryMB:       512,
			MaxNetworkBytes:   1048576,
		},
		Readiness: ReadinessDeploymentConfig{
			LivenessCheckEnabled:  true,
			ReadinessCheckEnabled: true,
			SecurityCheckEnabled:  false,
			RequireFreshAssurance: false,
		},
	}
}

// DefaultSecureConfig returns a baseline secure profile with mandatory authorizations.
func DefaultSecureConfig() DeploymentConfig {
	return DeploymentConfig{
		Version:     1,
		Profile:     ProfileSecure,
		Environment: "staging",
		Topology:    TopologySingleProcess,
		Gateway: GatewayDeploymentConfig{
			AudienceID: "runtime://skil-secure",
		},
		Enforcement: EnforcementDeploymentConfig{
			MandatoryAuthorization:  true,
			RequireProofCarrying:    true,
			AuditOutcomePersistence: true,
			FailClosed:              true,
		},
		MCP: MCPDeploymentConfig{
			RequireSurfaceLock: true,
			SurfaceLockPath:    ".skil/mcp-surface.lock.json",
			ValidateSchemas:    true,
			StrictTools:        true,
		},
		Replay: ReplayDeploymentConfig{
			Scope: receipt.ReplayScopeProcessLocal,
		},
		Assurance: AssuranceDeploymentConfig{
			OracleEnabled:                    true,
			MaxReconciliationIntervalSeconds: 600,
			FreshnessThresholdSeconds:        3600,
			RequireActiveReconciliation:      true,
		},
		Resources: ResourceDeploymentConfig{
			MaxToolCalls:      16,
			MaxRuntimeSeconds: 15,
			MaxMemoryMB:       1024,
			MaxNetworkBytes:   5242880,
		},
		Readiness: ReadinessDeploymentConfig{
			LivenessCheckEnabled:  true,
			ReadinessCheckEnabled: true,
			SecurityCheckEnabled:  true,
			RequireFreshAssurance: true,
		},
	}
}

// DefaultProductionConfig returns the mandatory production profile.
func DefaultProductionConfig() DeploymentConfig {
	cfg := DefaultSecureConfig()
	cfg.Profile = ProfileProduction
	cfg.Environment = "production"
	cfg.Topology = TopologyMultiProcessHost
	cfg.Gateway.AudienceID = "runtime://skil-production"
	cfg.Gateway.KeyRotation = KeyRotationConfig{
		MaxKeyAgeHours:     720,
		RotationNoticeDays: 14,
		RequireActiveKey:   true,
	}
	cfg.Replay.Scope = receipt.ReplayScopeHostDurable
	cfg.Replay.DurableDir = "/var/run/skil/nonces"
	cfg.Assurance.MaxReconciliationIntervalSeconds = 300
	cfg.Assurance.FreshnessThresholdSeconds = 1800
	cfg.Resources.MaxToolCalls = 16
	cfg.Resources.MaxRuntimeSeconds = 10
	cfg.Resources.MaxMemoryMB = 2048
	cfg.Resources.MaxNetworkBytes = 10485760
	return cfg
}

// ValidateProfileTransition ensures valid profile inheritance and migration paths.
// Production must not silently downgrade to development or compatibility behavior.
func ValidateProfileTransition(from, to ProfileName) error {
	level := func(p ProfileName) int {
		switch p {
		case ProfileDevelopment:
			return 1
		case ProfileSecure:
			return 2
		case ProfileProduction:
			return 3
		default:
			return 0
		}
	}
	fromLvl, toLvl := level(from), level(to)
	if fromLvl > toLvl {
		return fmt.Errorf("transition from %q to %q is prohibited (downgrade prevention: production and secure workloads must not be downgraded)", from, to)
	}
	return nil
}

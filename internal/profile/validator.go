package profile

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/mcpassure"
	"github.com/domehahn/skil/internal/receipt"
)

type ValidationSeverity string

const (
	SeverityCritical ValidationSeverity = "CRITICAL"
	SeverityHigh     ValidationSeverity = "HIGH"
	SeverityMedium   ValidationSeverity = "MEDIUM"
	SeverityLow      ValidationSeverity = "LOW"
	SeverityInfo     ValidationSeverity = "INFO"
)

// ValidationFinding represents a structured security control evaluation finding.
type ValidationFinding struct {
	ControlID       string             `json:"control_id"`
	Severity        ValidationSeverity `json:"severity"`
	Profile         ProfileName        `json:"profile"`
	EffectiveConfig string             `json:"effective_config"`
	ExpectedConfig  string             `json:"expected_config"`
	Evidence        string             `json:"evidence"`
	Remediation     string             `json:"remediation"`
	Blocking        bool               `json:"blocking"`
}

// ValidationReport aggregates all startup validation findings and determines
// whether the deployment can safely proceed.
type ValidationReport struct {
	Profile       ProfileName         `json:"profile"`
	Environment   string              `json:"environment"`
	Topology      DeploymentTopology  `json:"topology"`
	Valid         bool                `json:"valid"`
	Blocked       bool                `json:"blocked"`
	BlockingCount int                 `json:"blocking_count"`
	Findings      []ValidationFinding `json:"findings"`
	EvaluatedAt   time.Time           `json:"evaluated_at"`
	Summary       string              `json:"summary"`
}

var secretValuePattern = regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9]{16,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----|bearer\s+[a-zA-Z0-9_\-\.]{16,})`)

// LiveEnvironmentState allows the validator to inspect optional live host bindings.
type LiveEnvironmentState struct {
	OracleAvailable     bool
	SurfaceLockOverride *mcpassure.SurfaceLock
	ReplayLedger        *receipt.NonceLedger
	ActiveSigningKeys   map[string]time.Time // KeyID -> registered/rotated time
	Now                 func() time.Time
}

// ValidateStartup performs mandatory typed startup security validation against
// the requested profile and deployment topology.
func ValidateStartup(cfg DeploymentConfig, live LiveEnvironmentState) ValidationReport {
	now := time.Now().UTC()
	if live.Now != nil {
		now = live.Now().UTC()
	}

	cfg.Normalize()
	report := ValidationReport{
		Profile:     cfg.Profile,
		Environment: cfg.Environment,
		Topology:    cfg.Topology,
		EvaluatedAt: now,
		Findings:    make([]ValidationFinding, 0),
	}

	addFinding := func(finding ValidationFinding) {
		if finding.Blocking {
			report.BlockingCount++
			report.Blocked = true
		}
		report.Findings = append(report.Findings, finding)
	}

	// 1. Secret Exposure Guard (Never print private keys or credential tokens)
	rawCfg, _ := json.Marshal(cfg)
	if secretValuePattern.Match(rawCfg) {
		addFinding(ValidationFinding{
			ControlID:       "SEC-SECRET-001",
			Severity:        SeverityCritical,
			Profile:         cfg.Profile,
			EffectiveConfig: "[DETECTED RAW CREDENTIALS IN CONFIGURATION]",
			ExpectedConfig:  "Configuration must never contain private keys, bearer tokens, or raw credentials",
			Evidence:        "Config contains raw sensitive credential strings",
			Remediation:     "Remove embedded credentials; reference external KeyIDs, vaults, or environment variables",
			Blocking:        true,
		})
	}

	// 2. Profile & Environment Consistency
	switch cfg.Profile {
	case ProfileProduction:
		lowerEnv := strings.ToLower(cfg.Environment)
		if strings.Contains(lowerEnv, "dev") || strings.Contains(lowerEnv, "test") || strings.Contains(lowerEnv, "local") {
			addFinding(ValidationFinding{
				ControlID:       "SEC-PROF-001",
				Severity:        SeverityCritical,
				Profile:         cfg.Profile,
				EffectiveConfig: fmt.Sprintf("environment=%q", cfg.Environment),
				ExpectedConfig:  "production or explicit enterprise production tier",
				Evidence:        "Production profile declared with non-production environment name",
				Remediation:     "Set environment to a production tier or change profile to development/secure",
				Blocking:        true,
			})
		}
	case ProfileDevelopment:
		addFinding(ValidationFinding{
			ControlID:       "SEC-PROF-002",
			Severity:        SeverityInfo,
			Profile:         cfg.Profile,
			EffectiveConfig: "profile=development",
			ExpectedConfig:  "development profile is for local testing only; NOT for production workloads",
			Evidence:        "Running with development profile",
			Remediation:     "Promote to secure or production profile before deploying to shared or production environments",
			Blocking:        false,
		})
	}

	// 3. ExecutionGateway Audience Configuration
	if strings.TrimSpace(cfg.Gateway.AudienceID) == "" {
		isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
		addFinding(ValidationFinding{
			ControlID:       "SEC-GW-001",
			Severity:        SeverityCritical,
			Profile:         cfg.Profile,
			EffectiveConfig: "audience_id=\"\"",
			ExpectedConfig:  "URI formatted runtime audience ID (e.g. runtime://skil-prod)",
			Evidence:        "Gateway audience ID is empty",
			Remediation:     "Configure gateway.audience_id with the canonical runtime identity",
			Blocking:        isBlocking,
		})
	} else if u, err := url.Parse(cfg.Gateway.AudienceID); err != nil || u.Scheme == "" {
		isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
		addFinding(ValidationFinding{
			ControlID:       "SEC-GW-002",
			Severity:        SeverityHigh,
			Profile:         cfg.Profile,
			EffectiveConfig: fmt.Sprintf("audience_id=%q", cfg.Gateway.AudienceID),
			ExpectedConfig:  "Valid URI formatted audience (scheme://identity)",
			Evidence:        fmt.Sprintf("Invalid audience URI: %v", err),
			Remediation:     "Format gateway.audience_id as a valid URI (e.g. runtime://cluster-prod-1)",
			Blocking:        isBlocking,
		})
	}

	// 4. Trusted Issuers & Public Signing Keys
	if len(cfg.Gateway.TrustedIssuers) == 0 {
		isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
		addFinding(ValidationFinding{
			ControlID:       "SEC-KEY-001",
			Severity:        SeverityCritical,
			Profile:         cfg.Profile,
			EffectiveConfig: "trusted_issuers={}",
			ExpectedConfig:  "At least one trusted issuer ID and key ID mapping",
			Evidence:        "No trusted authorization issuers are configured",
			Remediation:     "Configure gateway.trusted_issuers with approved signing authorities",
			Blocking:        isBlocking,
		})
	}
	if len(cfg.Gateway.TrustedPublicKeys) == 0 {
		isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
		addFinding(ValidationFinding{
			ControlID:       "SEC-KEY-002",
			Severity:        SeverityCritical,
			Profile:         cfg.Profile,
			EffectiveConfig: "trusted_public_keys={}",
			ExpectedConfig:  "Public keys mapped to trusted issuer key IDs",
			Evidence:        "No trusted public verification keys configured",
			Remediation:     "Configure gateway.trusted_public_keys with base64 Ed25519 public keys",
			Blocking:        isBlocking,
		})
	} else {
		for keyID, pubB64 := range cfg.Gateway.TrustedPublicKeys {
			raw, err := base64.StdEncoding.DecodeString(pubB64)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				addFinding(ValidationFinding{
					ControlID:       "SEC-KEY-003",
					Severity:        SeverityCritical,
					Profile:         cfg.Profile,
					EffectiveConfig: fmt.Sprintf("key_id=%s, len=%d", keyID, len(raw)),
					ExpectedConfig:  "Valid 32-byte base64-encoded Ed25519 public key",
					Evidence:        fmt.Sprintf("Public key %s failed validation: %v", keyID, err),
					Remediation:     "Replace with valid Ed25519 public key bytes",
					Blocking:        true,
				})
			}
		}

		// Ensure all keys referenced by trusted issuers exist in trusted_public_keys
		for issuerID, keyIDs := range cfg.Gateway.TrustedIssuers {
			for _, kid := range keyIDs {
				if _, exists := cfg.Gateway.TrustedPublicKeys[kid]; !exists {
					isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
					addFinding(ValidationFinding{
						ControlID:       "SEC-KEY-004",
						Severity:        SeverityCritical,
						Profile:         cfg.Profile,
						EffectiveConfig: fmt.Sprintf("issuer=%q references key_id=%q", issuerID, kid),
						ExpectedConfig:  "Every issuer key ID must have a corresponding public key in trusted_public_keys",
						Evidence:        fmt.Sprintf("Key ID %q for issuer %q is missing from trusted_public_keys", kid, issuerID),
						Remediation:     "Add corresponding public key to gateway.trusted_public_keys",
						Blocking:        isBlocking,
					})
				}
			}
		}
	}

	// 5. Key Rotation & Freshness (Production requirement)
	if cfg.Profile == ProfileProduction {
		if cfg.Gateway.KeyRotation.MaxKeyAgeHours <= 0 {
			addFinding(ValidationFinding{
				ControlID:       "SEC-ROT-001",
				Severity:        SeverityHigh,
				Profile:         cfg.Profile,
				EffectiveConfig: fmt.Sprintf("max_key_age_hours=%d", cfg.Gateway.KeyRotation.MaxKeyAgeHours),
				ExpectedConfig:  "max_key_age_hours > 0 (e.g. 720 hours / 30 days)",
				Evidence:        "Production requires configured key rotation maximum age",
				Remediation:     "Configure gateway.key_rotation.max_key_age_hours",
				Blocking:        true,
			})
		}
	}

	// 6. Mandatory Proof-Carrying Authorization
	if !cfg.Enforcement.MandatoryAuthorization || !cfg.Enforcement.RequireProofCarrying {
		isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
		addFinding(ValidationFinding{
			ControlID:       "SEC-AUTH-001",
			Severity:        SeverityCritical,
			Profile:         cfg.Profile,
			EffectiveConfig: fmt.Sprintf("mandatory_authorization=%t, require_proof_carrying=%t", cfg.Enforcement.MandatoryAuthorization, cfg.Enforcement.RequireProofCarrying),
			ExpectedConfig:  "mandatory_authorization=true and require_proof_carrying=true",
			Evidence:        "Protected execution paths permit bypass without proof-carrying token",
			Remediation:     "Set enforcement.mandatory_authorization=true and enforcement.require_proof_carrying=true",
			Blocking:        isBlocking,
		})
	}

	// 7. Fail-Closed Default
	if !cfg.Enforcement.FailClosed {
		isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
		addFinding(ValidationFinding{
			ControlID:       "SEC-FAILCLOSE-001",
			Severity:        SeverityCritical,
			Profile:         cfg.Profile,
			EffectiveConfig: "fail_closed=false",
			ExpectedConfig:  "fail_closed=true",
			Evidence:        "Security enforcement configured with permissive fallback on error",
			Remediation:     "Set enforcement.fail_closed=true",
			Blocking:        isBlocking,
		})
	}

	// 8. MCP Surface Lock & Schema Parity
	if !cfg.MCP.RequireSurfaceLock {
		isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
		addFinding(ValidationFinding{
			ControlID:       "SEC-LOCK-001",
			Severity:        SeverityHigh,
			Profile:         cfg.Profile,
			EffectiveConfig: "require_surface_lock=false",
			ExpectedConfig:  "require_surface_lock=true",
			Evidence:        "MCP surface lock is disabled, allowing runtime dynamic tool poisoning",
			Remediation:     "Set mcp.require_surface_lock=true",
			Blocking:        isBlocking,
		})
	} else {
		lockPath := strings.TrimSpace(cfg.MCP.SurfaceLockPath)
		if live.SurfaceLockOverride == nil {
			if lockPath == "" {
				addFinding(ValidationFinding{
					ControlID:       "SEC-LOCK-002",
					Severity:        SeverityCritical,
					Profile:         cfg.Profile,
					EffectiveConfig: "surface_lock_path=\"\"",
					ExpectedConfig:  "Path to valid non-empty MCP surface lock file",
					Evidence:        "MCP surface lock path is not configured",
					Remediation:     "Specify mcp.surface_lock_path pointing to a verified surface lock",
					Blocking:        true,
				})
			} else {
				data, err := os.ReadFile(lockPath)
				if err != nil {
					addFinding(ValidationFinding{
						ControlID:       "SEC-LOCK-003",
						Severity:        SeverityCritical,
						Profile:         cfg.Profile,
						EffectiveConfig: fmt.Sprintf("surface_lock_path=%q", lockPath),
						ExpectedConfig:  "Existing, readable Surface Lock file",
						Evidence:        fmt.Sprintf("Failed to read Surface Lock file: %v", err),
						Remediation:     "Generate and verify MCP surface lock with `skil mcp lock`",
						Blocking:        true,
					})
				} else {
					var lock mcpassure.SurfaceLock
					if err := json.Unmarshal(data, &lock); err != nil || len(lock.Tools) == 0 {
						addFinding(ValidationFinding{
							ControlID:       "SEC-LOCK-004",
							Severity:        SeverityCritical,
							Profile:         cfg.Profile,
							EffectiveConfig: fmt.Sprintf("tools_count=%d", len(lock.Tools)),
							ExpectedConfig:  "Valid surface lock JSON with at least one pinned tool",
							Evidence:        "Surface Lock file is invalid JSON or has empty tools map",
							Remediation:     "Re-pin tools in MCP surface lock with `skil mcp lock`",
							Blocking:        true,
						})
					}
				}
			}
		}
	}

	// 9. Multi-Instance Replay Protection & Topology Match (Phase 3)
	switch cfg.Topology {
	case TopologySingleProcess:
		if cfg.Profile == ProfileProduction && cfg.Replay.Scope != receipt.ReplayScopeHostDurable {
			addFinding(ValidationFinding{
				ControlID:       "SEC-REPLAY-001",
				Severity:        SeverityMedium,
				Profile:         cfg.Profile,
				EffectiveConfig: fmt.Sprintf("topology=%s, scope=%s", cfg.Topology, cfg.Replay.Scope),
				ExpectedConfig:  "host-durable replay protection across process restarts",
				Evidence:        "Process-local nonce ledger does not survive service restarts",
				Remediation:     "Set replay.scope=host-durable and configure replay.durable_dir",
				Blocking:        false, // Allowed in single-process, but warned
			})
		}
	case TopologyMultiProcessHost:
		if cfg.Replay.Scope != receipt.ReplayScopeHostDurable {
			isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
			addFinding(ValidationFinding{
				ControlID:       "SEC-REPLAY-002",
				Severity:        SeverityCritical,
				Profile:         cfg.Profile,
				EffectiveConfig: fmt.Sprintf("topology=%s, scope=%s", cfg.Topology, cfg.Replay.Scope),
				ExpectedConfig:  "replay.scope=host-durable with shared durable_dir",
				Evidence:        "Multi-process on single host requires host-durable atomic file ledger",
				Remediation:     "Set replay.scope=host-durable and provide accessible replay.durable_dir",
				Blocking:        isBlocking,
			})
		} else if strings.TrimSpace(cfg.Replay.DurableDir) == "" {
			addFinding(ValidationFinding{
				ControlID:       "SEC-REPLAY-003",
				Severity:        SeverityCritical,
				Profile:         cfg.Profile,
				EffectiveConfig: "durable_dir=\"\"",
				ExpectedConfig:  "Non-empty path to host durable nonce directory",
				Evidence:        "Host-durable scope configured without storage directory",
				Remediation:     "Set replay.durable_dir to a secure host directory",
				Blocking:        true,
			})
		}
	case TopologyDistributed:
		// Phase 3 requirement: Host-local durable storage must NOT be accepted as distributed replay protection!
		// If distributed protection is required but unavailable, reject production startup rather than claiming coverage.
		if cfg.Replay.Scope != "distributed" || strings.TrimSpace(cfg.Replay.DistributedStore) == "" {
			isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
			addFinding(ValidationFinding{
				ControlID:       "SEC-REPLAY-004",
				Severity:        SeverityCritical,
				Profile:         cfg.Profile,
				EffectiveConfig: fmt.Sprintf("topology=%s, scope=%s, distributed_store=%q", cfg.Topology, cfg.Replay.Scope, cfg.Replay.DistributedStore),
				ExpectedConfig:  "Verified distributed consensus store with scope=distributed",
				Evidence:        "Distributed topology requires external consensus replay store; host-local storage cannot provide multi-host replay protection",
				Remediation:     "Configure approved distributed replay store or change deployment topology to single_process / multi_process_host",
				Blocking:        isBlocking,
			})
		}
	}

	// 10. Continuous Re-Assurance & Oracle
	if !cfg.Assurance.OracleEnabled {
		isBlocking := cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction
		addFinding(ValidationFinding{
			ControlID:       "SEC-ASSURE-001",
			Severity:        SeverityHigh,
			Profile:         cfg.Profile,
			EffectiveConfig: "oracle_enabled=false",
			ExpectedConfig:  "oracle_enabled=true",
			Evidence:        "Continuous assurance validity oracle is disabled; runtime cannot react to drift",
			Remediation:     "Set assurance.oracle_enabled=true and connect continuous.Engine",
			Blocking:        isBlocking,
		})
	}
	if cfg.Profile == ProfileProduction {
		if cfg.Assurance.MaxReconciliationIntervalSeconds <= 0 || cfg.Assurance.FreshnessThresholdSeconds <= 0 {
			addFinding(ValidationFinding{
				ControlID:       "SEC-ASSURE-002",
				Severity:        SeverityHigh,
				Profile:         cfg.Profile,
				EffectiveConfig: fmt.Sprintf("reconcile_sec=%d, fresh_sec=%d", cfg.Assurance.MaxReconciliationIntervalSeconds, cfg.Assurance.FreshnessThresholdSeconds),
				ExpectedConfig:  "Positive reconciliation interval and freshness threshold",
				Evidence:        "Production requires configured drift reconciliation intervals",
				Remediation:     "Set max_reconciliation_interval_seconds and freshness_threshold_seconds",
				Blocking:        true,
			})
		}
	}

	// 11. Audit Outcome Persistence (Production requirement)
	if cfg.Profile == ProfileProduction {
		if !cfg.Enforcement.AuditOutcomePersistence || strings.TrimSpace(cfg.Enforcement.AuditLogPath) == "" {
			addFinding(ValidationFinding{
				ControlID:       "SEC-AUDIT-001",
				Severity:        SeverityHigh,
				Profile:         cfg.Profile,
				EffectiveConfig: fmt.Sprintf("audit_persistence=%t, log_path=%q", cfg.Enforcement.AuditOutcomePersistence, cfg.Enforcement.AuditLogPath),
				ExpectedConfig:  "audit_outcome_persistence=true with valid audit_log_path",
				Evidence:        "Production requires persisted immutable audit trail for all enforcement decisions",
				Remediation:     "Set enforcement.audit_outcome_persistence=true and specify enforcement.audit_log_path",
				Blocking:        true,
			})
		}
	}

	// 12. Bounded Execution Limits (Production requirement)
	if cfg.Profile == ProfileProduction {
		if cfg.Resources.MaxToolCalls <= 0 || cfg.Resources.MaxRuntimeSeconds <= 0 || cfg.Resources.MaxMemoryMB <= 0 {
			addFinding(ValidationFinding{
				ControlID:       "SEC-BOUNDS-001",
				Severity:        SeverityHigh,
				Profile:         cfg.Profile,
				EffectiveConfig: fmt.Sprintf("tool_calls=%d, runtime_sec=%d, memory_mb=%d", cfg.Resources.MaxToolCalls, cfg.Resources.MaxRuntimeSeconds, cfg.Resources.MaxMemoryMB),
				ExpectedConfig:  "Positive resource limits for tools, runtime duration, and memory",
				Evidence:        "Production execution without resource bounds risks resource exhaustion",
				Remediation:     "Set resources.max_tool_calls, resources.max_runtime_seconds, and resources.max_memory_mb",
				Blocking:        true,
			})
		}
	}

	// 13. Security Readiness Gating
	if !cfg.Readiness.SecurityCheckEnabled && (cfg.Profile == ProfileSecure || cfg.Profile == ProfileProduction) {
		addFinding(ValidationFinding{
			ControlID:       "SEC-READY-001",
			Severity:        SeverityHigh,
			Profile:         cfg.Profile,
			EffectiveConfig: "security_check_enabled=false",
			ExpectedConfig:  "security_check_enabled=true",
			Evidence:        "Security readiness gating is disabled",
			Remediation:     "Set readiness.security_check_enabled=true",
			Blocking:        true,
		})
	}

	report.Valid = (report.BlockingCount == 0)
	if report.Valid {
		report.Summary = fmt.Sprintf("Deployment profile %q is VALID for environment %q (topology=%s, findings=%d)",
			cfg.Profile, cfg.Environment, cfg.Topology, len(report.Findings))
	} else {
		report.Summary = fmt.Sprintf("Deployment profile %q is BLOCKED for environment %q (%d blocking findings, %d total)",
			cfg.Profile, cfg.Environment, report.BlockingCount, len(report.Findings))
	}

	return report
}

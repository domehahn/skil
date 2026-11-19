package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

type GateStatus string

const (
	GateStatusReady      GateStatus = "READY"
	GateStatusNotReady   GateStatus = "NOT_READY"
	GateStatusIncomplete GateStatus = "INCOMPLETE"
)

type ReleaseCheckStatus string

const (
	CheckPass    ReleaseCheckStatus = "PASS"
	CheckFail    ReleaseCheckStatus = "FAIL"
	CheckIncompl ReleaseCheckStatus = "INCOMPLETE"
	CheckSkip    ReleaseCheckStatus = "SKIPPED"
)

// ReleaseGateCheck records individual evaluation of one of the 10 release checks.
type ReleaseGateCheck struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Status      ReleaseCheckStatus `json:"status"`
	Mandatory   bool               `json:"mandatory"`
	Detail      string             `json:"detail"`
	Remediation string             `json:"remediation,omitempty"`
}

// ReleaseGateReport is the machine-readable output of the release security gate.
type ReleaseGateReport struct {
	Status      GateStatus           `json:"status"`
	Profile     ProfileName          `json:"profile"`
	Environment string               `json:"environment"`
	Topology    DeploymentTopology   `json:"topology"`
	Checks      []ReleaseGateCheck   `json:"checks"`
	Findings    []ValidationFinding  `json:"findings,omitempty"`
	Readiness   OperationalReadiness `json:"readiness"`
	EvaluatedAt time.Time            `json:"evaluated_at"`
	Summary     string               `json:"summary"`
}

// ReleaseGateOptions configures the release gate verification context.
type ReleaseGateOptions struct {
	Config          DeploymentConfig
	LiveReadiness   *ReadinessTracker
	ArtifactPath    string
	AttestationPath string
	PolicyPath      string
	Now             func() time.Time
}

// EvaluateReleaseGate performs comprehensive evaluation of all 10 release criteria.
func EvaluateReleaseGate(opts ReleaseGateOptions) ReleaseGateReport {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}

	cfg := opts.Config
	cfg.Normalize()

	report := ReleaseGateReport{
		Profile:     cfg.Profile,
		Environment: cfg.Environment,
		Topology:    cfg.Topology,
		Checks:      make([]ReleaseGateCheck, 0, 10),
		EvaluatedAt: now,
	}

	// Step 1: Run startup validator
	valReport := ValidateStartup(cfg, LiveEnvironmentState{Now: opts.Now})
	report.Findings = valReport.Findings

	// Step 2: Check operational readiness if provided
	if opts.LiveReadiness != nil {
		report.Readiness = opts.LiveReadiness.Check()
	} else {
		report.Readiness = OperationalReadiness{
			Status:      StatusHealthy,
			Liveness:    true,
			Profile:     cfg.Profile,
			Environment: cfg.Environment,
			LastChecked: now,
		}
	}

	// 1. Mandatory production controls
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-01-PROD-CONTROLS",
			Name:      "Mandatory Production Controls",
			Mandatory: true,
		}
		if valReport.Blocked {
			c.Status = CheckFail
			c.Detail = fmt.Sprintf("%d blocking startup validation findings identified", valReport.BlockingCount)
			c.Remediation = "Resolve all blocking findings in startup validation report"
		} else {
			c.Status = CheckPass
			c.Detail = fmt.Sprintf("All %s profile mandatory controls satisfied", cfg.Profile)
		}
		report.Checks = append(report.Checks, c)
	}

	// 2. Runtime enforcement integration
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-02-RUNTIME-ENFORCEMENT",
			Name:      "Runtime Enforcement Integration",
			Mandatory: true,
		}
		if cfg.Enforcement.MandatoryAuthorization && cfg.Enforcement.RequireProofCarrying {
			c.Status = CheckPass
			c.Detail = "Mandatory proof-carrying authorization enforced on execution paths"
		} else if cfg.Profile == ProfileDevelopment {
			c.Status = CheckPass
			c.Detail = "Development profile: permissive execution allowed for testing"
		} else {
			c.Status = CheckFail
			c.Detail = "Runtime enforcement is disabled or does not require proof-carrying tokens"
			c.Remediation = "Enable enforcement.mandatory_authorization and enforcement.require_proof_carrying"
		}
		report.Checks = append(report.Checks, c)
	}

	// 3. MCP authorization coverage
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-03-MCP-AUTH",
			Name:      "MCP Authorization Coverage",
			Mandatory: true,
		}
		if cfg.MCP.RequireSurfaceLock && cfg.MCP.ValidateSchemas {
			c.Status = CheckPass
			c.Detail = "MCP Surface Lock and live schema verification active"
		} else if cfg.Profile == ProfileDevelopment {
			c.Status = CheckPass
			c.Detail = "Development profile: MCP surface lock optional"
		} else {
			c.Status = CheckFail
			c.Detail = "MCP Surface Lock or schema validation is missing"
			c.Remediation = "Enable mcp.require_surface_lock and mcp.validate_schemas"
		}
		report.Checks = append(report.Checks, c)
	}

	// 4. Assurance freshness
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-04-ASSURANCE-FRESHNESS",
			Name:      "Assurance Freshness & Reconciliation",
			Mandatory: true,
		}
		if opts.LiveReadiness != nil {
			if report.Readiness.AssuranceFreshness {
				c.Status = CheckPass
				c.Detail = "Live assurance oracle active and reconciled within freshness window"
			} else {
				c.Status = CheckFail
				c.Detail = "Live assurance is stale or has reported drift"
				c.Remediation = "Reconcile continuous assurance dependencies"
			}
		} else {
			if cfg.Assurance.OracleEnabled && cfg.Assurance.MaxReconciliationIntervalSeconds > 0 {
				c.Status = CheckPass
				c.Detail = fmt.Sprintf("Assurance oracle configured with %ds reconciliation window", cfg.Assurance.MaxReconciliationIntervalSeconds)
			} else if cfg.Profile == ProfileDevelopment {
				c.Status = CheckPass
				c.Detail = "Development profile: continuous reconciliation disabled"
			} else {
				c.Status = CheckFail
				c.Detail = "Assurance oracle is not configured in secure/production profile"
				c.Remediation = "Enable assurance.oracle_enabled and set max_reconciliation_interval_seconds"
			}
		}
		report.Checks = append(report.Checks, c)
	}

	// 5. Replay-protection suitability
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-05-REPLAY-SUITABILITY",
			Name:      "Replay-Protection Topology Suitability",
			Mandatory: true,
		}
		switch cfg.Topology {
		case TopologySingleProcess:
			c.Status = CheckPass
			c.Detail = fmt.Sprintf("Topology single_process satisfied by %s ledger", cfg.Replay.Scope)
		case TopologyMultiProcessHost:
			if cfg.Replay.Scope == "host-durable" && strings.TrimSpace(cfg.Replay.DurableDir) != "" {
				c.Status = CheckPass
				c.Detail = "Host-durable atomic replay protection configured for multi-process topology"
			} else {
				c.Status = CheckFail
				c.Detail = "Multi-process host requires host-durable replay protection"
				c.Remediation = "Configure replay.scope=host-durable and replay.durable_dir"
			}
		case TopologyDistributed:
			if cfg.Replay.Scope == "distributed" && strings.TrimSpace(cfg.Replay.DistributedStore) != "" {
				c.Status = CheckPass
				c.Detail = "Distributed consensus replay store configured"
			} else {
				c.Status = CheckFail
				c.Detail = "Distributed topology cannot accept host-local storage for replay protection"
				c.Remediation = "Provide verified distributed store or reconfigure topology"
			}
		default:
			c.Status = CheckFail
			c.Detail = fmt.Sprintf("Unknown deployment topology %q", cfg.Topology)
		}
		report.Checks = append(report.Checks, c)
	}

	// 6. Certificate verification
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-06-CERT-VERIFICATION",
			Name:      "Attestation & Certificate Verification",
			Mandatory: cfg.Profile == ProfileProduction,
		}
		if opts.AttestationPath != "" {
			attData, err := os.ReadFile(opts.AttestationPath)
			if err != nil {
				c.Status = CheckFail
				c.Detail = fmt.Sprintf("Failed to read attestation: %v", err)
			} else {
				var att skil.Attestation
				if err := json.Unmarshal(attData, &att); err != nil {
					c.Status = CheckFail
					c.Detail = fmt.Sprintf("Malformed attestation JSON: %v", err)
				} else if len(cfg.Gateway.TrustedPublicKeys) > 0 {
					if err := signing.VerifyAttestation(att, cfg.Gateway.TrustedPublicKeys); err != nil {
						c.Status = CheckFail
						c.Detail = fmt.Sprintf("Attestation cryptographic verification failed: %v", err)
						c.Remediation = "Verify attestation signature using configured trusted public keys"
					} else {
						c.Status = CheckPass
						c.Detail = "Attestation signature verified against trusted public keys"
					}
				} else {
					c.Status = CheckPass
					c.Detail = "Attestation parsed successfully (no trusted public keys specified)"
				}
			}
		} else if cfg.Profile == ProfileProduction {
			c.Status = CheckIncompl
			c.Detail = "No attestation file provided for release verification"
			c.Remediation = "Provide --attestation path to evaluate deployment release readiness"
		} else {
			c.Status = CheckSkip
			c.Detail = "Attestation verification skipped in non-production profile"
		}
		report.Checks = append(report.Checks, c)
	}

	// 7. Policy integrity
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-07-POLICY-INTEGRITY",
			Name:      "Policy Integrity & Validation",
			Mandatory: true,
		}
		polPath := cfg.Assurance.PolicyPath
		if opts.PolicyPath != "" {
			polPath = opts.PolicyPath
		}
		if polPath != "" {
			if _, err := policy.Load(polPath); err != nil {
				c.Status = CheckFail
				c.Detail = fmt.Sprintf("Failed to load policy %q: %v", polPath, err)
				c.Remediation = "Fix policy schema errors or provide valid policy file"
			} else {
				c.Status = CheckPass
				c.Detail = fmt.Sprintf("Policy %q is valid and loadable", polPath)
			}
		} else if cfg.Profile == ProfileProduction {
			c.Status = CheckIncompl
			c.Detail = "No policy path specified in production configuration"
			c.Remediation = "Specify assurance.policy_path"
		} else {
			c.Status = CheckPass
			c.Detail = "Using default built-in policy"
		}
		report.Checks = append(report.Checks, c)
	}

	// 8. Fail-closed behavior
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-08-FAIL-CLOSED",
			Name:      "Fail-Closed Security Posture",
			Mandatory: true,
		}
		if cfg.Enforcement.FailClosed {
			c.Status = CheckPass
			c.Detail = "Fail-closed behavior is enabled across all enforcement gates"
		} else if cfg.Profile == ProfileDevelopment {
			c.Status = CheckPass
			c.Detail = "Development profile: permissive fallback permitted"
		} else {
			c.Status = CheckFail
			c.Detail = "Fail-closed behavior is disabled in secure/production profile"
			c.Remediation = "Set enforcement.fail_closed=true"
		}
		report.Checks = append(report.Checks, c)
	}

	// 9. Configuration consistency
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-09-CONFIG-CONSISTENCY",
			Name:      "Configuration Consistency",
			Mandatory: true,
		}
		hasConflict := false
		var conflicts []string
		if cfg.Profile == ProfileProduction && cfg.Enforcement.MandatoryAuthorization && len(cfg.Gateway.TrustedPublicKeys) == 0 {
			hasConflict = true
			conflicts = append(conflicts, "Production mandatory authorization requires trusted public keys")
		}
		if cfg.Profile == ProfileProduction && cfg.Topology == TopologyMultiProcessHost && cfg.Replay.Scope != "host-durable" {
			hasConflict = true
			conflicts = append(conflicts, "Multi-process topology requires host-durable scope")
		}
		if hasConflict {
			c.Status = CheckFail
			c.Detail = strings.Join(conflicts, "; ")
			c.Remediation = "Resolve configuration conflicts in deployment profile"
		} else {
			c.Status = CheckPass
			c.Detail = "Deployment profile configuration is internally consistent"
		}
		report.Checks = append(report.Checks, c)
	}

	// 10. Known unresolved security limitations
	{
		c := ReleaseGateCheck{
			ID:        "CHECK-10-UNRESOLVED-LIMITATIONS",
			Name:      "Security Limitations & Residual Risk",
			Mandatory: true,
		}
		var limitations []string
		if cfg.Replay.Scope == "host-durable" {
			limitations = append(limitations, "Host-durable nonces protect single node only; multi-host clusters require distributed store")
		}
		if cfg.Profile == ProfileDevelopment {
			limitations = append(limitations, "Development profile disables cryptographic authorization and drift gating")
		}
		if len(limitations) > 0 {
			c.Status = CheckPass // Recognized limitations are tracked
			c.Detail = fmt.Sprintf("Known residual risks documented: %s", strings.Join(limitations, "; "))
		} else {
			c.Status = CheckPass
			c.Detail = "No unclassified security limitations recorded"
		}
		report.Checks = append(report.Checks, c)
	}

	// Synthesize overall gate status
	hasFail := false
	hasIncompl := false
	for _, ch := range report.Checks {
		if ch.Status == CheckFail {
			hasFail = true
		} else if ch.Status == CheckIncompl && ch.Mandatory {
			hasIncompl = true
		}
	}

	if valReport.Blocked || hasFail {
		report.Status = GateStatusNotReady
		report.Summary = fmt.Sprintf("RELEASE GATE NOT READY: Profile %q for %q failed mandatory release checks", cfg.Profile, cfg.Environment)
	} else if hasIncompl {
		report.Status = GateStatusIncomplete
		report.Summary = fmt.Sprintf("RELEASE GATE INCOMPLETE: Profile %q requires missing prerequisites before release approval", cfg.Profile)
	} else {
		report.Status = GateStatusReady
		report.Summary = fmt.Sprintf("RELEASE GATE READY: Profile %q for %q satisfies all release security criteria", cfg.Profile, cfg.Environment)
	}

	return report
}

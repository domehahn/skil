package profile

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/domehahn/skil/internal/continuous"
	"github.com/domehahn/skil/internal/receipt"
)

type ReadinessStatus string

const (
	StatusHealthy         ReadinessStatus = "HEALTHY"
	StatusDegraded        ReadinessStatus = "DEGRADED"
	StatusSecurityBlocked ReadinessStatus = "SECURITY_BLOCKED"
	StatusUnhealthy       ReadinessStatus = "UNHEALTHY"
)

// OperationalReadiness captures distinct operational dimensions.
type OperationalReadiness struct {
	Status              ReadinessStatus   `json:"status"`
	Liveness            bool              `json:"liveness"`
	DependencyReadiness bool              `json:"dependency_readiness"`
	SecurityReadiness   bool              `json:"security_readiness"`
	AssuranceFreshness  bool              `json:"assurance_freshness"`
	Profile             ProfileName       `json:"profile"`
	Environment         string            `json:"environment"`
	Details             map[string]string `json:"details"`
	LastChecked         time.Time         `json:"last_checked"`
}

// LiveReadinessContext encapsulates live runtime subsystems for health & security checking.
type LiveReadinessContext struct {
	ProcessStartedAt    time.Time
	Gateway             *receipt.ExecutionGateway
	ContinuousEngine    *continuous.Engine
	SubjectDigest       string
	AssuranceEvidenceID string
	PolicyDigest        string
	DecisionID          string
	SurfaceLockPath     string
	DurableNonceDir     string
	Now                 func() time.Time
}

// ReadinessTracker maintains thread-safe operational state across requests.
type ReadinessTracker struct {
	mu     sync.RWMutex
	cfg    DeploymentConfig
	ctx    LiveReadinessContext
	lastOp OperationalReadiness
}

func NewReadinessTracker(cfg DeploymentConfig, liveCtx LiveReadinessContext) *ReadinessTracker {
	cfg.Normalize()
	if liveCtx.Now == nil {
		liveCtx.Now = func() time.Time { return time.Now().UTC() }
	}
	t := &ReadinessTracker{
		cfg: cfg,
		ctx: liveCtx,
	}
	t.lastOp = t.Evaluate()
	return t
}

// Check evaluates the current operational readiness and updates internal state.
func (t *ReadinessTracker) Check() OperationalReadiness {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastOp = t.evaluateLocked()
	return t.lastOp
}

// IsOperationPermitted checks whether a new protected operation is allowed to proceed
// based on current security readiness. If SecurityReadiness is false, operations are blocked.
func (t *ReadinessTracker) IsOperationPermitted() (bool, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.cfg.Profile == ProfileDevelopment {
		return true, ""
	}
	if !t.lastOp.SecurityReadiness {
		return false, fmt.Sprintf("operation blocked by security readiness gate: %s", t.lastOp.Details["security"])
	}
	if !t.lastOp.AssuranceFreshness && t.cfg.Readiness.RequireFreshAssurance {
		return false, fmt.Sprintf("operation blocked by assurance freshness gate: %s", t.lastOp.Details["freshness"])
	}
	return true, ""
}

func (t *ReadinessTracker) Evaluate() OperationalReadiness {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.evaluateLocked()
}

func (t *ReadinessTracker) evaluateLocked() OperationalReadiness {
	now := t.ctx.Now().UTC()
	details := make(map[string]string)

	liveness := true
	dependencyReady := true
	securityReady := true
	assuranceFresh := true

	// 1. Process Liveness
	details["liveness"] = "process running"

	// 2. Dependency Readiness: Check local surface lock & durable nonce directory
	if t.ctx.SurfaceLockPath != "" {
		if _, err := os.Stat(t.ctx.SurfaceLockPath); err != nil {
			dependencyReady = false
			details["dependency_surface_lock"] = fmt.Sprintf("unreachable surface lock path: %v", err)
		} else {
			details["dependency_surface_lock"] = "accessible"
		}
	}
	if t.ctx.DurableNonceDir != "" {
		if fi, err := os.Stat(t.ctx.DurableNonceDir); err != nil || !fi.IsDir() {
			dependencyReady = false
			details["dependency_nonce_dir"] = fmt.Sprintf("unreachable durable nonce dir: %v", err)
		} else {
			details["dependency_nonce_dir"] = "accessible"
		}
	}

	// 3. Security Readiness: Check ExecutionGateway & ContinuousEngine
	if t.cfg.Enforcement.MandatoryAuthorization {
		if t.ctx.Gateway == nil {
			securityReady = false
			details["security"] = "ExecutionGateway is not initialized"
		} else {
			details["security"] = "ExecutionGateway active and enforcing"
		}
	}

	// 4. Assurance Freshness: Consult continuous engine oracle
	if t.cfg.Assurance.OracleEnabled && t.ctx.ContinuousEngine != nil {
		if t.ctx.SubjectDigest != "" {
			valid, reason := t.ctx.ContinuousEngine.IsAssuranceValid(
				t.ctx.SubjectDigest,
				t.ctx.AssuranceEvidenceID,
				t.ctx.PolicyDigest,
				t.ctx.DecisionID,
			)
			if !valid {
				assuranceFresh = false
				securityReady = false // Drift/staleness directly impacts security readiness!
				details["freshness"] = fmt.Sprintf("assurance invalid or drifted: %s", reason)
				details["security"] = fmt.Sprintf("assurance invalidation cascades to security gate: %s", reason)
			} else {
				details["freshness"] = "assurance valid and reconciled"
			}
		}
	}

	status := StatusHealthy
	if !securityReady {
		status = StatusSecurityBlocked
	} else if !dependencyReady {
		status = StatusDegraded
	} else if !liveness {
		status = StatusUnhealthy
	}

	return OperationalReadiness{
		Status:              status,
		Liveness:            liveness,
		DependencyReadiness: dependencyReady,
		SecurityReadiness:   securityReady,
		AssuranceFreshness:  assuranceFresh,
		Profile:             t.cfg.Profile,
		Environment:         t.cfg.Environment,
		Details:             details,
		LastChecked:         now,
	}
}

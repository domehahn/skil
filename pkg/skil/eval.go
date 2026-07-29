package skil

import "context"

type EvalSpec struct {
	Version     int               `json:"version" yaml:"version"`
	Name        string            `json:"name" yaml:"name"`
	Type        string            `json:"type" yaml:"type"`
	Input       EvalInput         `json:"input" yaml:"input"`
	Context     map[string]string `json:"context,omitempty" yaml:"context,omitempty"`
	Environment map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`
	Tools       EvalTools         `json:"tools" yaml:"tools"`
	Expect      EvalExpect        `json:"expect" yaml:"expect"`
	Attack      *Attack           `json:"attack,omitempty" yaml:"attack,omitempty"`
	Containment *EvalContainment  `json:"containment,omitempty" yaml:"containment,omitempty"`
}
type EvalContainment struct {
	Required               bool                `json:"required" yaml:"required"`
	AllowedTargets         map[string][]string `json:"allowed_targets,omitempty" yaml:"allowed_targets,omitempty"`
	RequireEnforcement     bool                `json:"require_enforcement,omitempty" yaml:"require_enforcement,omitempty"`
	RequireNativeIsolation bool                `json:"require_native_isolation,omitempty" yaml:"require_native_isolation,omitempty"`
}
type EvalInput struct {
	Message string `json:"message" yaml:"message"`
}
type EvalTools struct {
	Available []string `json:"available" yaml:"available"`
}
type EvalExpect struct {
	Required              []string          `json:"required,omitempty" yaml:"required,omitempty"`
	Allowed               []string          `json:"allowed,omitempty" yaml:"allowed,omitempty"`
	Forbidden             []string          `json:"forbidden,omitempty" yaml:"forbidden,omitempty"`
	ForbiddenCapabilities []string          `json:"forbidden_capabilities,omitempty" yaml:"forbidden_capabilities,omitempty"`
	Arguments             map[string]string `json:"arguments,omitempty" yaml:"arguments,omitempty"`
	OutputProperties      []string          `json:"output_properties,omitempty" yaml:"output_properties,omitempty"`
	Assertions            []string          `json:"assertions,omitempty" yaml:"assertions,omitempty"`
}
type Attack struct {
	Category string `json:"category" yaml:"category"`
}

const (
	AttackDirectInjection            = "direct-injection"
	AttackIndirectInjection          = "indirect-injection"
	AttackToolOutputPoisoning        = "tool-output-poisoning"
	AttackRAGPoisoning               = "rag-poisoning"
	AttackREADMEPoisoning            = "readme-poisoning"
	AttackMCPPoisoning               = "mcp-poisoning"
	AttackSecretExtraction           = "secret-extraction"
	AttackPermissionBypass           = "permission-bypass"
	AttackRoleEscalation             = "role-escalation"
	AttackMemoryPoisoning            = "memory-poisoning"
	AttackCrossAgentInjection        = "cross-agent-injection"
	AttackSocialEngineering          = "social-engineering"
	AttackContainmentEscape          = "containment-escape"
	AttackPrivilegeEscalation        = "privilege-escalation"
	AttackLateralMovement            = "lateral-movement"
	AttackGoalBoundaryViolation      = "goal-boundary-violation"
	AttackUnauthorizedExternalAction = "unauthorized-external-action"
	AttackEnforcementBypass          = "enforcement-bypass"
)

type EvalRequest struct {
	Test     EvalSpec `json:"test"`
	Artifact Artifact `json:"artifact"`
	Run      int      `json:"run"`
}

// GatewayTool is implemented by trusted host-side tools. Operation must derive
// the enforceable capability from validated arguments; the untrusted adapter
// never supplies its own authorization claim.
type GatewayTool interface {
	Operation(arguments map[string]any) (Operation, error)
	Execute(context.Context, map[string]any) (any, error)
}

type GatewayResult struct {
	ID     string `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
	Denied bool   `json:"denied,omitempty"`
}

type GatewayExchange struct {
	Version int             `json:"version"`
	Request EvalRequest     `json:"request"`
	Results []GatewayResult `json:"results"`
}

type GatewayMessage struct {
	Type      string         `json:"type"`
	ID        string         `json:"id,omitempty"`
	Tool      string         `json:"tool,omitempty"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Final     *EvalTrace     `json:"final,omitempty"`
}
type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Allowed   bool           `json:"allowed"`
}

type ContainmentViolation struct {
	Category   string    `json:"category"`
	Capability string    `json:"capability"`
	Operation  Operation `json:"operation"`
	Target     string    `json:"target,omitempty"`
	Denied     bool      `json:"denied"`
	SideEffect bool      `json:"side_effect"`
	Step       int       `json:"step"`
	Tool       string    `json:"tool,omitempty"`
	Reason     string    `json:"reason"`
	Constraint string    `json:"contract_constraint,omitempty"`
}

type EvalTrace struct {
	Messages              []string               `json:"messages"`
	ToolCalls             []ToolCall             `json:"tool_calls"`
	Operations            []Operation            `json:"operations,omitempty"`
	ContainmentViolations []ContainmentViolation `json:"containment_violations,omitempty"`
	Outputs               []string               `json:"outputs"`
	SideEffects           []string               `json:"side_effects"`
	Capabilities          []string               `json:"capabilities"`
	Errors                []string               `json:"errors"`
}
type EvalRun struct {
	Run                  int       `json:"run"`
	Passed               bool      `json:"passed"`
	TaskSucceeded        bool      `json:"task_succeeded"`
	PolicyCompliant      bool      `json:"policy_compliant"`
	CapabilityCompliant  bool      `json:"capability_compliant"`
	ContainmentCompliant bool      `json:"containment_compliant"`
	Violations           []string  `json:"violations"`
	Trace                EvalTrace `json:"trace"`
}
type EvalMetrics struct {
	TaskSuccessRate                float64  `json:"task_success_rate"`
	PolicyComplianceRate           float64  `json:"policy_compliance_rate"`
	UnauthorizedToolCallRate       float64  `json:"unauthorized_tool_call_rate"`
	AttackSuccessRate              float64  `json:"prompt_injection_attack_success_rate"`
	SecretExfiltrationRate         float64  `json:"secret_exfiltration_rate"`
	ToolSelectionAccuracy          float64  `json:"tool_selection_accuracy"`
	ContainmentComplianceRate      *float64 `json:"containment_compliance_rate,omitempty"`
	ContainmentEscapeAttemptRate   *float64 `json:"containment_escape_attempt_rate,omitempty"`
	PrivilegeEscalationAttemptRate *float64 `json:"privilege_escalation_attempt_rate,omitempty"`
	LateralMovementAttemptRate     *float64 `json:"lateral_movement_attempt_rate,omitempty"`
	UnauthorizedExternalActionRate *float64 `json:"unauthorized_external_action_rate,omitempty"`
	GoalBoundaryViolationRate      *float64 `json:"goal_boundary_violation_rate,omitempty"`
	EnforcementBypassAttemptRate   *float64 `json:"enforcement_bypass_attempt_rate,omitempty"`
}

type EvalCoverage struct {
	Behavioral      CoverageState `json:"behavioral"`
	Containment     CoverageState `json:"containment"`
	Enforcement     CoverageState `json:"enforcement"`
	Isolation       CoverageState `json:"isolation"`
	NativeIsolation CoverageState `json:"native_isolation"`
	RuntimeMode     string        `json:"runtime_mode"`
}

type EvalResult struct {
	SchemaVersion  string       `json:"schema_version"`
	Test           string       `json:"test"`
	ArtifactDigest string       `json:"artifact_digest"`
	EvalSpecDigest string       `json:"eval_spec_digest"`
	Runtime        string       `json:"runtime"`
	Coverage       EvalCoverage `json:"coverage"`
	Runs           []EvalRun    `json:"runs"`
	Metrics        EvalMetrics  `json:"metrics"`
	Status         Status       `json:"status"`
}

type RuntimeAssurance struct {
	Enforcement     bool
	Isolation       bool
	NativeIsolation bool
	Mode            string
}

type AssuranceRuntime interface {
	AgentRuntime
	Assurance() RuntimeAssurance
}

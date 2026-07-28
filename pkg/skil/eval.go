package skil

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
type EvalRequest struct {
	Test     EvalSpec
	Artifact Artifact
	Run      int
}
type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Allowed   bool           `json:"allowed"`
}
type EvalTrace struct {
	Messages     []string   `json:"messages"`
	ToolCalls    []ToolCall `json:"tool_calls"`
	Outputs      []string   `json:"outputs"`
	SideEffects  []string   `json:"side_effects"`
	Capabilities []string   `json:"capabilities"`
	Errors       []string   `json:"errors"`
}
type EvalRun struct {
	Run        int       `json:"run"`
	Passed     bool      `json:"passed"`
	Violations []string  `json:"violations"`
	Trace      EvalTrace `json:"trace"`
}
type EvalMetrics struct {
	TaskSuccessRate          float64 `json:"task_success_rate"`
	PolicyComplianceRate     float64 `json:"policy_compliance_rate"`
	UnauthorizedToolCallRate float64 `json:"unauthorized_tool_call_rate"`
	AttackSuccessRate        float64 `json:"prompt_injection_attack_success_rate"`
	SecretExfiltrationRate   float64 `json:"secret_exfiltration_rate"`
	ToolSelectionAccuracy    float64 `json:"tool_selection_accuracy"`
}
type EvalResult struct {
	Test    string      `json:"test"`
	Runtime string      `json:"runtime"`
	Runs    []EvalRun   `json:"runs"`
	Metrics EvalMetrics `json:"metrics"`
	Status  Status      `json:"status"`
}

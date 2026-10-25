package receipt

import (
	"errors"
	"fmt"
)

// EnforcementMode makes fail-open versus fail-closed behavior explicit.
type EnforcementMode string

const (
	ModeObserve EnforcementMode = "OBSERVE"
	ModeAdvise  EnforcementMode = "ADVISE"
	ModeEnforce EnforcementMode = "ENFORCE"
)

// GateAction is what the caller must do with the operation.
type GateAction string

const (
	ActionAllow GateAction = "ALLOW"
	ActionWarn  GateAction = "ALLOW_WITH_WARNING"
	ActionDeny  GateAction = "DENY"
)

// DecideGate resolves the action for a security gate. Only OBSERVE and ADVISE
// may proceed when verification is unavailable or the verdict is block, and
// only OBSERVE/ADVISE ever fail open. ENFORCE is fail-closed unless an
// authorized policy explicitly permits fail-open for unavailable verification
// (a block verdict is never overridden in ENFORCE).
func DecideGate(mode EnforcementMode, verificationAvailable, blocked, failOpenAuthorized bool) (GateAction, error) {
	switch mode {
	case ModeObserve:
		return ActionAllow, nil
	case ModeAdvise:
		if blocked || !verificationAvailable {
			return ActionWarn, nil
		}
		return ActionAllow, nil
	case ModeEnforce:
		if blocked {
			return ActionDeny, nil
		}
		if !verificationAvailable {
			if failOpenAuthorized {
				return ActionWarn, nil
			}
			return ActionDeny, nil
		}
		return ActionAllow, nil
	}
	return ActionDeny, fmt.Errorf("unknown enforcement mode %q", mode)
}

// EnforcementStage separates the distinct things a runtime can report.
type EnforcementStage string

const (
	StageAttempted EnforcementStage = "INVOCATION_ATTEMPTED"
	StageTransport EnforcementStage = "TRANSPORT_SUCCEEDED"
	StageAccepted  EnforcementStage = "OPERATION_ACCEPTED"
	StageEnforced  EnforcementStage = "OPERATION_ENFORCED"
	StageFailed    EnforcementStage = "ENFORCEMENT_FAILED"
)

// EnforcementAck is the protocol-specific success payload; HTTP status or a
// zero exit code alone never constitute acceptance.
type EnforcementAck struct {
	Accepted     bool   `json:"accepted"`
	Enforced     bool   `json:"enforced"`
	PolicyDigest string `json:"policy_digest"`
	Error        string `json:"error,omitempty"`
}

// EnforcementReceipt binds an enforcement outcome to the policy decision,
// subject, runtime and invocation it applies to.
type EnforcementReceipt struct {
	Stage                EnforcementStage `json:"stage"`
	PolicyDecisionDigest string           `json:"policy_decision_digest"`
	SubjectDigest        string           `json:"subject_digest"`
	RuntimeIdentity      string           `json:"runtime_identity"`
	InvocationID         string           `json:"invocation_id"`
	TransportStatus      int              `json:"transport_status,omitempty"`
	ExitCode             int              `json:"exit_code,omitempty"`
	Ack                  *EnforcementAck  `json:"ack,omitempty"`
}

type EnforcementExpectation struct {
	PolicyDecisionDigest string
	SubjectDigest        string
	RuntimeIdentity      string
	InvocationID         string
}

// ValidateEnforcement accepts a receipt only if it proves the operation was
// actually enforced under exactly the expected decision, subject, runtime and
// invocation. A failed operation can never validate as an accepted receipt.
func ValidateEnforcement(r EnforcementReceipt, want EnforcementExpectation) error {
	if want.PolicyDecisionDigest == "" || want.SubjectDigest == "" || want.RuntimeIdentity == "" || want.InvocationID == "" {
		return errors.New("expectation is incomplete; refusing to validate against unspecified identity")
	}
	if r.PolicyDecisionDigest != want.PolicyDecisionDigest {
		return errors.New("receipt is bound to a different policy decision")
	}
	if r.SubjectDigest != want.SubjectDigest {
		return errors.New("receipt is bound to a different subject")
	}
	if r.RuntimeIdentity != want.RuntimeIdentity {
		return errors.New("receipt is from a different runtime")
	}
	if r.InvocationID != want.InvocationID {
		return errors.New("receipt is for a different invocation")
	}
	switch r.Stage {
	case StageEnforced:
	case StageFailed:
		return errors.New("enforcement failed")
	default:
		return fmt.Errorf("stage %s does not prove enforcement", r.Stage)
	}
	if r.Ack == nil {
		return errors.New("no protocol acknowledgement payload")
	}
	if r.Ack.Error != "" || !r.Ack.Accepted || !r.Ack.Enforced {
		return errors.New("acknowledgement does not report accepted and enforced")
	}
	if r.Ack.PolicyDigest != want.PolicyDecisionDigest {
		return errors.New("acknowledgement is bound to a different policy")
	}
	if r.TransportStatus != 0 && (r.TransportStatus < 200 || r.TransportStatus > 299) {
		return fmt.Errorf("transport status %d", r.TransportStatus)
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("non-zero exit code %d", r.ExitCode)
	}
	return nil
}

package trust

import (
	"time"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/pkg/skil"
)

// TrustLevel represents the canonical governance trust classification of a skill.
type TrustLevel string

const (
	LevelUntrusted  TrustLevel = "UNTRUSTED"
	LevelRestricted TrustLevel = "RESTRICTED"
	LevelReviewed   TrustLevel = "REVIEWED"
	LevelTrusted    TrustLevel = "TRUSTED"
	LevelVerified   TrustLevel = "VERIFIED"
	LevelRevoked    TrustLevel = "REVOKED"
)

// TrustDeduction accounts for a specific reduction in trust score.
type TrustDeduction struct {
	Category       string  `json:"category" yaml:"category"`
	RuleID         string  `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	PointsDeducted float64 `json:"points_deducted" yaml:"points_deducted"`
	Reason         string  `json:"reason" yaml:"reason"`
	Evidence       string  `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// TrustBreakdown details the score across individual governance dimensions.
type TrustBreakdown struct {
	SecurityScore         float64 `json:"security_score" yaml:"security_score"`
	QualityScore          float64 `json:"quality_score" yaml:"quality_score"`
	EvaluationScore       float64 `json:"evaluation_score" yaml:"evaluation_score"`
	ProvenanceScore       float64 `json:"provenance_score" yaml:"provenance_score"`
	PermissionRiskScore   float64 `json:"permission_risk_score" yaml:"permission_risk_score"`
	DuplicateRiskScore    float64 `json:"duplicate_risk_score" yaml:"duplicate_risk_score"`
	RuntimeStabilityScore float64 `json:"runtime_stability_score" yaml:"runtime_stability_score"`
}

// TrustScore represents the aggregate explainable trust score (0-100).
type TrustScore struct {
	Score      float64          `json:"score" yaml:"score"`
	Breakdown  TrustBreakdown   `json:"breakdown" yaml:"breakdown"`
	Deductions []TrustDeduction `json:"deductions,omitempty" yaml:"deductions,omitempty"`
}

// TrustAssessment is the complete, exportable trust assessment of a skill.
type TrustAssessment struct {
	ArtifactName      string                     `json:"artifact_name" yaml:"artifact_name"`
	Version           string                     `json:"version,omitempty" yaml:"version,omitempty"`
	Digest            string                     `json:"digest" yaml:"digest"`
	TrustScore        TrustScore                 `json:"trust_score" yaml:"trust_score"`
	TrustLevel        TrustLevel                 `json:"trust_level" yaml:"trust_level"`
	AdmissionDecision registry.AdmissionDecision `json:"admission_decision" yaml:"admission_decision"`
	Recommendations   []string                   `json:"recommendations,omitempty" yaml:"recommendations,omitempty"`
	Timestamp         time.Time                  `json:"timestamp" yaml:"timestamp"`
}

// TrustWeights configures the weighted evaluation of trust score components.
type TrustWeights struct {
	SecurityWeight         float64 `json:"security_weight" yaml:"security_weight"`
	QualityWeight          float64 `json:"quality_weight" yaml:"quality_weight"`
	EvaluationWeight       float64 `json:"evaluation_weight" yaml:"evaluation_weight"`
	ProvenanceWeight       float64 `json:"provenance_weight" yaml:"provenance_weight"`
	PermissionWeight       float64 `json:"permission_weight" yaml:"permission_weight"`
	DuplicateWeight        float64 `json:"duplicate_weight" yaml:"duplicate_weight"`
	RuntimeStabilityWeight float64 `json:"runtime_stability_weight" yaml:"runtime_stability_weight"`
}

// DefaultTrustWeights returns standard platform weight distribution totaling 1.0.
func DefaultTrustWeights() TrustWeights {
	return TrustWeights{
		SecurityWeight:         0.30,
		QualityWeight:          0.15,
		EvaluationWeight:       0.20,
		ProvenanceWeight:       0.15,
		PermissionWeight:       0.10,
		DuplicateWeight:        0.05,
		RuntimeStabilityWeight: 0.05,
	}
}

// TrustInputs aggregates all multi-domain analysis evidence for trust calculation.
type TrustInputs struct {
	Artifact        *skil.Artifact
	Findings        []skil.Finding
	QualityFindings []skil.Finding
	DuplicateResult *registry.DuplicateAnalysisResult
	SkillLift       float64 // e.g. 0.214 for +21.4%
	PassAtK         float64 // e.g. 0.95 for 95% pass rate
	IsSigned        bool
	HasProvenance   bool
	IsRevoked       bool
}

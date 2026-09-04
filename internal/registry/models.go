package registry

import (
	"time"
)

type RelationshipType string

const (
	RelationshipExactDuplicate    RelationshipType = "EXACT_DUPLICATE"
	RelationshipSemanticDuplicate RelationshipType = "SEMANTIC_DUPLICATE"
	RelationshipHighSimilarity    RelationshipType = "HIGH_SIMILARITY"
	RelationshipCapabilityOverlap RelationshipType = "CAPABILITY_OVERLAP"
	RelationshipSubset            RelationshipType = "SUBSET"
	RelationshipSuperset          RelationshipType = "SUPERSET"
	RelationshipComplementary     RelationshipType = "COMPLEMENTARY"
	RelationshipRelated           RelationshipType = "RELATED"
	RelationshipDistinct          RelationshipType = "DISTINCT"
	RelationshipUnknown           RelationshipType = "UNKNOWN"
)

type AdmissionDecision string

const (
	DecisionAccept            AdmissionDecision = "ACCEPT"
	DecisionAcceptWithWarning AdmissionDecision = "ACCEPT_WITH_WARNING"
	DecisionReview            AdmissionDecision = "REVIEW"
	DecisionReject            AdmissionDecision = "REJECT"
)

type FingerprintInfo struct {
	Algorithm      string `json:"algorithm"`
	Value          string `json:"value"`
	FileCount      int    `json:"file_count"`
	CanonicalBytes int64  `json:"canonical_bytes"`
}

type CapabilityFingerprint struct {
	Domain       []string `json:"domain,omitempty"`
	Actions      []string `json:"actions,omitempty"`
	Tools        []string `json:"tools,omitempty"`
	Resources    []string `json:"resources,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	Integrations []string `json:"integrations,omitempty"`
	Inputs       []string `json:"inputs,omitempty"`
	Outputs      []string `json:"outputs,omitempty"`
}

type Metadata struct {
	Name            string   `json:"name"`
	Title           string   `json:"title,omitempty"`
	Description     string   `json:"description,omitempty"`
	Version         string   `json:"version,omitempty"`
	Namespace       string   `json:"namespace,omitempty"`
	Author          string   `json:"author,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Categories      []string `json:"categories,omitempty"`
	Repository      string   `json:"repository,omitempty"`
	Commit          string   `json:"commit,omitempty"`
	Publisher       string   `json:"publisher,omitempty"`
	SignatureStatus string   `json:"signature_status,omitempty"`
}

type CatalogEntry struct {
	ID                  string                `json:"id"`
	Name                string                `json:"name"`
	Version             string                `json:"version"`
	Namespace           string                `json:"namespace,omitempty"`
	Fingerprint         FingerprintInfo       `json:"fingerprint"`
	SemanticFingerprint string                `json:"semantic_fingerprint,omitempty"`
	Embedding           []float32             `json:"embedding,omitempty"`
	Capabilities        CapabilityFingerprint `json:"capabilities"`
	Metadata            Metadata              `json:"metadata"`
	ScanTimestamp       time.Time             `json:"scan_timestamp"`
}

type SimilarityScore struct {
	Name       float64 `json:"name"`
	Semantic   float64 `json:"semantic"`
	Capability float64 `json:"capability"`
	Overall    float64 `json:"overall"`
}

type CapabilityOverlapResult struct {
	ActionOverlap           float64  `json:"action_overlap"`
	ToolOverlap             float64  `json:"tool_overlap"`
	ResourceOverlap         float64  `json:"resource_overlap"`
	PermissionOverlap       float64  `json:"permission_overlap"`
	OverallScore            float64  `json:"overall_score"`
	UniqueCapabilities      []string `json:"unique_capabilities,omitempty"`
	OverlappingCapabilities []string `json:"overlapping_capabilities,omitempty"`
}

type DuplicateMatch struct {
	Entry            CatalogEntry            `json:"entry"`
	Relationship     RelationshipType        `json:"relationship"`
	Scores           SimilarityScore         `json:"scores"`
	CapabilityDetail CapabilityOverlapResult `json:"capability_detail"`
}

type DuplicateAnalysisResult struct {
	Candidate      Metadata              `json:"candidate"`
	Fingerprint    FingerprintInfo       `json:"fingerprint"`
	Capabilities   CapabilityFingerprint `json:"capabilities"`
	Relationship   RelationshipType      `json:"relationship"`
	Matches        []DuplicateMatch      `json:"matches,omitempty"`
	Reason         string                `json:"reason"`
	Recommendation string                `json:"recommendation"`
}

type AdmissionResult struct {
	Decision                AdmissionDecision       `json:"decision"`
	Relationship            RelationshipType        `json:"relationship"`
	Candidate               string                  `json:"candidate"`
	MostSimilarSkill        string                  `json:"most_similar_skill,omitempty"`
	Scores                  SimilarityScore         `json:"scores"`
	CapabilityOverlap       CapabilityOverlapResult `json:"capability_overlap"`
	Reason                  string                  `json:"reason"`
	Recommendation          string                  `json:"recommendation"`
	UniqueCapabilities      []string                `json:"unique_capabilities,omitempty"`
	OverlappingCapabilities []string                `json:"overlapping_capabilities,omitempty"`
	AllowedBy               *AllowRule              `json:"allowed_by,omitempty"`
}

type ThresholdConfig struct {
	ExactAction            AdmissionDecision `yaml:"exact_action" json:"exact_action"`
	SemanticDuplicate      float64           `yaml:"semantic_duplicate" json:"semantic_duplicate"`
	SemanticHighSimilarity float64           `yaml:"semantic_high_similarity" json:"semantic_high_similarity"`
	SemanticRelated        float64           `yaml:"semantic_related" json:"semantic_related"`
	CapabilityDuplicate    float64           `yaml:"capability_duplicate" json:"capability_duplicate"`
	CapabilitySubset       float64           `yaml:"capability_subset" json:"capability_subset"`
	CapabilitySuperset     float64           `yaml:"capability_superset" json:"capability_superset"`
}

type RelationshipPolicies struct {
	ExactDuplicate    AdmissionDecision `yaml:"exact_duplicate" json:"exact_duplicate"`
	SemanticDuplicate AdmissionDecision `yaml:"semantic_duplicate" json:"semantic_duplicate"`
	HighSimilarity    AdmissionDecision `yaml:"high_similarity" json:"high_similarity"`
	CapabilityOverlap AdmissionDecision `yaml:"capability_overlap" json:"capability_overlap"`
	Subset            AdmissionDecision `yaml:"subset" json:"subset"`
	Superset          AdmissionDecision `yaml:"superset" json:"superset"`
	Complementary     AdmissionDecision `yaml:"complementary" json:"complementary"`
	Distinct          AdmissionDecision `yaml:"distinct" json:"distinct"`
}

type AllowRule struct {
	Candidate string    `yaml:"candidate" json:"candidate"`
	RelatedTo string    `yaml:"related_to" json:"related_to"`
	Reason    string    `yaml:"reason" json:"reason"`
	Owner     string    `yaml:"owner,omitempty" json:"owner,omitempty"`
	Expires   time.Time `yaml:"expires,omitempty" json:"expires,omitempty"`
}

type AdmissionConfig struct {
	Enabled    bool                 `yaml:"enabled" json:"enabled"`
	Thresholds ThresholdConfig      `yaml:"thresholds" json:"thresholds"`
	Policies   RelationshipPolicies `yaml:"policies" json:"policies"`
	AllowRules []AllowRule          `yaml:"allow" json:"allow"`
}

func DefaultAdmissionConfig() AdmissionConfig {
	return AdmissionConfig{
		Enabled: true,
		Thresholds: ThresholdConfig{
			ExactAction:            DecisionReject,
			SemanticDuplicate:      0.95,
			SemanticHighSimilarity: 0.90,
			SemanticRelated:        0.75,
			CapabilityDuplicate:    0.90,
			CapabilitySubset:       0.90,
			CapabilitySuperset:     0.90,
		},
		Policies: RelationshipPolicies{
			ExactDuplicate:    DecisionReject,
			SemanticDuplicate: DecisionReject,
			HighSimilarity:    DecisionReview,
			CapabilityOverlap: DecisionReview,
			Subset:            DecisionReject,
			Superset:          DecisionReview,
			Complementary:     DecisionAccept,
			Distinct:          DecisionAccept,
		},
		AllowRules: nil,
	}
}

// Package skil defines the stable, vendor-neutral public model and extension
// interfaces. Implementations live in internal packages; third-party analyzers
// and providers only need this package.
package skil

import (
	"context"
	"time"
)

const Version = "0.1.0"

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Status string

const (
	StatusPass  Status = "PASS"
	StatusWarn  Status = "WARN"
	StatusFail  Status = "FAIL"
	StatusError Status = "ERROR"
)

type Location struct {
	File      string `json:"file" yaml:"file"`
	StartLine int    `json:"start_line,omitempty" yaml:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty" yaml:"end_line,omitempty"`
}

type Finding struct {
	ID          string         `json:"id" yaml:"id"`
	RuleID      string         `json:"rule_id" yaml:"rule_id"`
	Category    string         `json:"category" yaml:"category"`
	Severity    Severity       `json:"severity" yaml:"severity"`
	Confidence  float64        `json:"confidence" yaml:"confidence"`
	Title       string         `json:"title" yaml:"title"`
	Message     string         `json:"message" yaml:"message"`
	Description string         `json:"description,omitempty" yaml:"description,omitempty"`
	Location    Location       `json:"location" yaml:"location"`
	Evidence    map[string]any `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	References  []string       `json:"references,omitempty" yaml:"references,omitempty"`
	Fingerprint string         `json:"fingerprint" yaml:"fingerprint"`
	Suppressed  bool           `json:"suppressed,omitempty" yaml:"suppressed,omitempty"`
}

type Rule struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Category    string   `json:"category" yaml:"category"`
	Severity    Severity `json:"severity" yaml:"severity"`
	Description string   `json:"description" yaml:"description"`
	Analysis    string   `json:"analysis" yaml:"analysis"`
	AppliesTo   []string `json:"applies_to" yaml:"applies_to"`
	Remediation string   `json:"remediation" yaml:"remediation"`
	References  []string `json:"references,omitempty" yaml:"references,omitempty"`
}

type File struct {
	Path       string `json:"path"`
	Data       []byte `json:"-"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable,omitempty"`
}

type Artifact struct {
	Name          string    `json:"name"`
	Version       string    `json:"version,omitempty"`
	Source        string    `json:"source"`
	Digest        string    `json:"content_manifest_sha256"`
	PackageDigest string    `json:"package_sha256,omitempty"`
	Files         []File    `json:"files"`
	Repository    string    `json:"source_repository,omitempty"`
	Commit        string    `json:"source_commit,omitempty"`
	Builder       string    `json:"builder,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// SubjectDigest returns the immutable transport digest when one exists and the
// reproducible content-manifest digest for unpackaged directories.
func (a Artifact) SubjectDigest() string {
	if a.PackageDigest != "" {
		return a.PackageDigest
	}
	return a.Digest
}

type CoverageState string

const (
	CoverageCompleted    CoverageState = "completed"
	CoverageNotAvailable CoverageState = "not_available"
	CoverageNotRequested CoverageState = "not_requested"
	CoverageNotRun       CoverageState = "not_run"
)

type ScanResult struct {
	SchemaVersion string                   `json:"schema_version"`
	Artifact      Artifact                 `json:"artifact"`
	Status        Status                   `json:"status"`
	RiskScore     int                      `json:"risk_score"`
	Maximum       Severity                 `json:"maximum_severity"`
	Findings      []Finding                `json:"findings"`
	Coverage      map[string]CoverageState `json:"analysis"`
	Scanners      []string                 `json:"scanners"`
	GeneratedAt   time.Time                `json:"generated_at"`
}

type AnalyzerMetadata struct {
	ID             string   `json:"id"`
	Version        string   `json:"version"`
	Categories     []string `json:"categories"`
	AnalysisTypes  []string `json:"analysis_types"`
	SupportedTypes []string `json:"supported_file_types"`
}

type AnalysisContext struct {
	Artifact Artifact
	Contract *SkillContract
}

type Analyzer interface {
	Metadata() AnalyzerMetadata
	Analyze(context.Context, AnalysisContext) ([]Finding, error)
}

type SemanticProvider interface {
	ID() string
	AnalyzeUntrusted(context.Context, SemanticRequest) ([]Finding, error)
}

type SemanticRequest struct {
	ArtifactDigest string            `json:"artifact_digest"`
	Files          map[string]string `json:"files"`
	Contract       *SkillContract    `json:"contract,omitempty"`
	NoTools        bool              `json:"no_tools"`
}

type Vulnerability struct {
	Package, Version, ID, Summary string
	Severity                      Severity
}

type VulnerabilityProvider interface {
	ID() string
	Query(context.Context, string, string, string) ([]Vulnerability, error)
}

type PackageReputation struct {
	Abandoned  bool
	LastUpdate time.Time
}

type PackageReputationProvider interface {
	Reputation(context.Context, string, string) (PackageReputation, error)
}

type SigningProvider interface {
	ID() string
	Sign(context.Context, string) ([]byte, error)
	Verify(context.Context, string, []byte) error
}

type EvidenceImporter interface {
	ID() string
	Import(context.Context, []byte, Artifact) ([]Evidence, error)
}

type AgentRuntime interface {
	ID() string
	Execute(context.Context, EvalRequest) (EvalTrace, error)
}

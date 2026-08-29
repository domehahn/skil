// Package skil defines the stable, vendor-neutral public model and extension
// interfaces. Implementations live in internal packages; third-party analyzers
// and providers only need this package.
package skil

import (
	"context"
	"time"
)

// Version is overridden from the release tag through -ldflags.
var Version = "0.1.0"

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

type Verdict string

const (
	VerdictClear  Verdict = "CLEAR"
	VerdictReview Verdict = "REVIEW"
	VerdictBlock  Verdict = "BLOCK"
)

// AssuranceState separates proven safety from both proven unsafety and an
// incomplete proof. UNKNOWN must never be treated as SAFE by policy,
// attestation, or runtime enforcement.
type AssuranceState string

const (
	AssuranceSafe    AssuranceState = "SAFE"
	AssuranceUnsafe  AssuranceState = "UNSAFE"
	AssuranceUnknown AssuranceState = "UNKNOWN"
)

type NodeKind string

const (
	NodeRoot              NodeKind = "root"
	NodeArtifact          NodeKind = "artifact"
	NodeDependency        NodeKind = "dependency"
	NodeExternalReference NodeKind = "external_reference"
	NodeNestedArtifact    NodeKind = "nested_artifact"
	NodeMCPSurface        NodeKind = "mcp_surface"
	NodeRuntimeArtifact   NodeKind = "runtime_artifact"
	NodeAgentSurface      NodeKind = "agent_execution_surface"
	NodePersistentState   NodeKind = "persistent_state"
)

type AnalysisStatus string

const (
	AnalysisCompleted  AnalysisStatus = "completed"
	AnalysisIncomplete AnalysisStatus = "incomplete"
	AnalysisFailed     AnalysisStatus = "failed"
	AnalysisNotRun     AnalysisStatus = "not_run"
)

type VerificationStatus string

const (
	VerificationVerified   VerificationStatus = "verified"
	VerificationFailed     VerificationStatus = "failed"
	VerificationUnresolved VerificationStatus = "unresolved"
	VerificationNotNeeded  VerificationStatus = "not_required"
)

type Location struct {
	File      string `json:"file" yaml:"file"`
	StartLine int    `json:"start_line,omitempty" yaml:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty" yaml:"end_line,omitempty"`
}

type Finding struct {
	ID                 string         `json:"id" yaml:"id"`
	RuleID             string         `json:"rule_id" yaml:"rule_id"`
	Category           string         `json:"category" yaml:"category"`
	Severity           Severity       `json:"severity" yaml:"severity"`
	Confidence         float64        `json:"confidence" yaml:"confidence"`
	Title              string         `json:"title" yaml:"title"`
	Message            string         `json:"message" yaml:"message"`
	Description        string         `json:"description,omitempty" yaml:"description,omitempty"`
	Location           Location       `json:"location" yaml:"location"`
	Evidence           map[string]any `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation        string         `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	References         []string       `json:"references,omitempty" yaml:"references,omitempty"`
	Fingerprint        string         `json:"fingerprint" yaml:"fingerprint"`
	Suppressed         bool           `json:"suppressed,omitempty" yaml:"suppressed,omitempty"`
	SuppressionReason  string         `json:"suppression_reason,omitempty" yaml:"suppression_reason,omitempty"`
	ContextDisposition string         `json:"context_disposition,omitempty" yaml:"context_disposition,omitempty"`
	ContextReason      string         `json:"context_reason,omitempty" yaml:"context_reason,omitempty"`
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
	// Encoding is the text encoding internal/artifact detected for Data
	// before transcoding it to canonical UTF-8 (e.g. "utf-16le") — see
	// internal/artifact's canonicalizeText. Empty for files constructed
	// without going through that loader (most direct skil.File{} literals
	// in tests). "utf-8" for the common case: already-UTF-8 content that
	// needed no transcoding. Absent (omitted from JSON) is not the same
	// as "utf-8" — it means no encoding detection ran at all.
	Encoding string `json:"encoding,omitempty"`
	// ContainerDepth is 0 for a file loaded directly from the top-level
	// artifact, and N for a file materialized by
	// internal/artifact.VirtualizeNestedContainers from the Nth level of
	// nested ZIP-compatible container virtualization (a .zip/.docx/.xlsx/
	// .pptx/... found as a regular file inside the artifact, itself
	// containing further files — possibly itself another such container).
	ContainerDepth int `json:"container_depth,omitempty"`
	// ContainerParentSHA256 is the raw-byte SHA-256 (the same convention
	// as SHA256 below: computed before any text canonicalization) of the
	// immediate container file this File was materialized from. Empty at
	// ContainerDepth 0.
	ContainerParentSHA256 string `json:"container_parent_sha256,omitempty"`
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
	// LoadDiagnostics carries any non-fatal condition encountered while
	// building Files — currently only nested-container virtualization
	// bounds (a container skipped or truncated by depth/member/byte/
	// compression-ratio/time limits). A bound being hit is deliberately
	// not a load error (the rest of the artifact still loads and scans
	// normally) but must still be visible, not silently absorbed.
	LoadDiagnostics []Diagnostic `json:"load_diagnostics,omitempty"`
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
	CoverageDegraded     CoverageState = "degraded"
	CoverageNotAvailable CoverageState = "not_available"
	CoverageNotRequested CoverageState = "not_requested"
	CoverageNotRun       CoverageState = "not_run"
)

type InspectionOutcome string

const (
	InspectionCompleted  InspectionOutcome = "completed"
	InspectionSkipped    InspectionOutcome = "skipped"
	InspectionFailed     InspectionOutcome = "failed"
	InspectionOutOfScope InspectionOutcome = "out_of_scope"
)

// InspectionWorkItem accounts for one analyzer/file decision. Out-of-scope
// entries are retained so consumers can distinguish deliberate routing from
// silently omitted work.
type InspectionWorkItem struct {
	Analyzer string            `json:"analyzer"`
	Version  string            `json:"analyzer_version"`
	File     string            `json:"file"`
	Outcome  InspectionOutcome `json:"outcome"`
	Reason   string            `json:"reason,omitempty"`
	Findings int               `json:"findings"`
}

type InspectionSummary struct {
	Total        int     `json:"total"`
	Applicable   int     `json:"applicable"`
	Completed    int     `json:"completed"`
	Skipped      int     `json:"skipped"`
	Failed       int     `json:"failed"`
	OutOfScope   int     `json:"out_of_scope"`
	Completeness float64 `json:"completeness"`
}

type Diagnostic struct {
	Component string `json:"component"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type AnalyzabilityState string

const (
	AnalyzabilityFull AnalyzabilityState = "full"
	// AnalyzabilityPartial is reserved for a file whose content is
	// partly but not fully visible to analysis — e.g. source that
	// failed to parse but still ran through pattern/regex rules, or
	// (not yet implemented) compiled bytecode correlated with an
	// available source file. No analyzer currently emits it; it exists
	// so AnalyzabilitySummary's schema doesn't need to change when one
	// does.
	AnalyzabilityPartial AnalyzabilityState = "partial"
	AnalyzabilityOpaque  AnalyzabilityState = "opaque"
)

// AnalyzabilityRecord classifies how visible one file's actual content
// was to analysis — a narrower question than InspectionWorkItem's "did
// an applicable analyzer run": a file can have every applicable analyzer
// report InspectionCompleted while its content remains opaque (e.g. a
// binary format skil has no parser for) rather than substantively
// inspected. Coverage completeness alone can't distinguish those two
// cases; this can.
type AnalyzabilityRecord struct {
	Path string `json:"path"`
	// Encoding mirrors File.Encoding: "utf-8"/"utf-8-bom"/"utf-16le"/
	// "utf-16be" for text, "binary" for anything canonicalizeText
	// couldn't decode as text.
	Encoding string `json:"encoding,omitempty"`
	// BinaryKind identifies a recognized executable/archive format
	// (e.g. "Windows PE executable") for a binary file, empty when the
	// binary format wasn't recognized or the file is text.
	BinaryKind string             `json:"binary_kind,omitempty"`
	Executable bool               `json:"executable,omitempty"`
	State      AnalyzabilityState `json:"state"`
	Reason     string             `json:"reason,omitempty"`
	SHA256     string             `json:"sha256"`
}

// AnalyzabilitySummary aggregates AnalyzabilityRecords the same way
// InspectionSummary aggregates the inspection ledger. Coverage credits a
// partial record at half weight: (full + 0.5*partial) / files.
type AnalyzabilitySummary struct {
	Files    int     `json:"files"`
	Full     int     `json:"full"`
	Partial  int     `json:"partial"`
	Opaque   int     `json:"opaque"`
	Coverage float64 `json:"coverage"`
}

type ScanResult struct {
	SchemaVersion string                   `json:"schema_version"`
	Artifact      Artifact                 `json:"artifact"`
	Status        Status                   `json:"status"`
	Verdict       Verdict                  `json:"verdict"`
	RiskScore     int                      `json:"risk_score"`
	Maximum       Severity                 `json:"maximum_severity"`
	Findings      []Finding                `json:"findings"`
	Observations  []CapabilityObservation  `json:"observations,omitempty"`
	Coverage      map[string]CoverageState `json:"analysis"`
	Scanners      []string                 `json:"scanners"`
	Inspection    []InspectionWorkItem     `json:"inspection_ledger,omitempty"`
	Completeness  InspectionSummary        `json:"inspection_summary"`
	Analyzability []AnalyzabilityRecord    `json:"analyzability_ledger,omitempty"`
	Analyzable    AnalyzabilitySummary     `json:"analyzability_summary"`
	Diagnostics   []Diagnostic             `json:"diagnostics,omitempty"`
	Budget        AnalysisBudgetUsage      `json:"analysis_budget"`
	// References is populated only when transitive reference scanning was
	// explicitly requested (skil scan --transitive) — nil/omitted
	// otherwise. skil never fetches external content on its own; this is
	// always an explicit, opt-in traversal the operator started.
	References  []ReferenceNode   `json:"references,omitempty"`
	Closure     *AssuranceClosure `json:"assurance_closure,omitempty"`
	GeneratedAt time.Time         `json:"generated_at"`
}

type AssuranceClosure struct {
	RootDigest       string         `json:"root_digest" yaml:"root_digest"`
	Nodes            []ClosureNode  `json:"nodes" yaml:"nodes"`
	Edges            []ClosureEdge  `json:"edges,omitempty" yaml:"edges,omitempty"`
	MaximumSeverity  Severity       `json:"maximum_severity" yaml:"maximum_severity"`
	Complete         bool           `json:"complete" yaml:"complete"`
	Limitations      []string       `json:"limitations,omitempty" yaml:"limitations,omitempty"`
	Digest           string         `json:"closure_digest" yaml:"closure_digest"`
	State            AssuranceState `json:"state" yaml:"state"`
	Verified         bool           `json:"verified" yaml:"verified"`
	RequiredNodes    int            `json:"required_nodes" yaml:"required_nodes"`
	UnresolvedNodes  int            `json:"unresolved_nodes" yaml:"unresolved_nodes"`
	BlockingFindings int            `json:"blocking_findings" yaml:"blocking_findings"`
	MaxDepth         int            `json:"max_depth" yaml:"max_depth"`
}

type ClosureNode struct {
	ID              string             `json:"id" yaml:"id"`
	Kind            NodeKind           `json:"kind,omitempty" yaml:"kind,omitempty"`
	Source          string             `json:"source" yaml:"source"`
	Digest          string             `json:"digest" yaml:"digest"`
	ParentDigest    string             `json:"parent_digest,omitempty" yaml:"parent_digest,omitempty"`
	Depth           int                `json:"depth" yaml:"depth"`
	ScanStatus      string             `json:"scan_status" yaml:"scan_status"`
	MaximumSeverity Severity           `json:"maximum_severity" yaml:"maximum_severity"`
	Verdict         string             `json:"verdict" yaml:"verdict"`
	Required        bool               `json:"required" yaml:"required"`
	Resolved        bool               `json:"resolved" yaml:"resolved"`
	Analyzed        bool               `json:"analyzed" yaml:"analyzed"`
	Findings        []string           `json:"findings,omitempty" yaml:"findings,omitempty"`
	AnalysisStatus  AnalysisStatus     `json:"analysis_status,omitempty" yaml:"analysis_status,omitempty"`
	Verification    VerificationStatus `json:"verification,omitempty" yaml:"verification,omitempty"`
}

type ClosureEdge struct {
	FromID   string `json:"from_id" yaml:"from_id"`
	ToID     string `json:"to_id" yaml:"to_id"`
	Relation string `json:"relation" yaml:"relation"`
}

// ReferenceNode is one external HTTPS reference found in a scanned
// artifact's own content (or in a previously-fetched reference's
// content), and what skil did about it — followed, or skipped, and why.
type ReferenceNode struct {
	URL       string `json:"url"`
	ParentURL string `json:"parent_url,omitempty"`
	Depth     int    `json:"depth"`
	Fetched   bool   `json:"fetched"`
	// SkipReason is set (and Fetched is false) when the reference was not
	// followed — denied by the allow/deny prefix policy, a budget already
	// exhausted, or a fetch/scan failure. A reference is always recorded
	// even when skipped, so the graph itself is a complete inventory of
	// what was found, not just what was followed.
	SkipReason string      `json:"skip_reason,omitempty"`
	Digest     string      `json:"digest,omitempty"`
	Scan       *ScanResult `json:"scan,omitempty"`
	// AlreadyDiscovered records an additional provenance edge to a URL that
	// was already materialized. The node is not fetched twice, but cycles and
	// duplicate references remain visible in the closure graph.
	AlreadyDiscovered bool `json:"already_discovered,omitempty"`
}

type AnalyzerMetadata struct {
	ID             string   `json:"id"`
	Version        string   `json:"version"`
	Domain         string   `json:"domain,omitempty"`
	Subdomain      string   `json:"subdomain,omitempty"`
	Categories     []string `json:"categories"`
	AnalysisTypes  []string `json:"analysis_types"`
	SupportedTypes []string `json:"supported_file_types"`
}

type AnalysisContext struct {
	Artifact     Artifact
	Contract     *SkillContract
	DomainFilter []string // empty = all domains; non-empty = only run analyzers matching these domains
	// Budget bounds the whole scan's aggregate resource consumption
	// (bytes analyzed, findings, inspection events, wall time) — a single
	// shared ceiling across every analyzer, not a per-analyzer-local one.
	// Nil uses DefaultAnalysisBudget.
	Budget *AnalysisBudget
}

// AnalysisBudget is the shared resource ceiling one scan's analyzers
// collectively draw from. Any dimension being exceeded raises the scan's
// overall Status to at least WARN and is recorded in AnalysisBudgetUsage —
// deliberately observability-and-gating rather than mid-scan truncation
// for every dimension: MaxWallTime is the one dimension actually enforced
// (via a context deadline derived from it, so every analyzer's own
// existing ctx.Err() checks stop real work early); the others are
// measured against the completed scan and reported, since silently
// truncating findings or file content mid-analysis would itself be a
// correctness risk skil's fail-closed philosophy exists to avoid.
type AnalysisBudget struct {
	MaxRawBytes         int64
	MaxExpandedBytes    int64
	MaxFindings         int
	MaxInspectionEvents int
	MaxWallTime         time.Duration
}

// DefaultAnalysisBudget is generous enough that no realistic skill scan
// hits it under normal use; it exists as a backstop against a pathological
// or adversarial artifact, not a routine constraint.
func DefaultAnalysisBudget() AnalysisBudget {
	return AnalysisBudget{
		MaxRawBytes: 100 << 20, MaxExpandedBytes: 150 << 20,
		MaxFindings: 10_000, MaxInspectionEvents: 200_000, MaxWallTime: 2 * time.Minute,
	}
}

// AnalysisBudgetUsage reports exactly what one scan consumed against
// AnalysisBudget, dimension by dimension, so the budget's role in a
// scan's outcome is as inspectable as any finding's evidence.
type AnalysisBudgetUsage struct {
	RawBytes         BudgetDimension `json:"raw_bytes"`
	ExpandedBytes    BudgetDimension `json:"expanded_bytes"`
	Findings         BudgetDimension `json:"findings"`
	InspectionEvents BudgetDimension `json:"inspection_events"`
	WallTime         BudgetDimension `json:"wall_time"`
	// Exceeded lists which dimensions (by JSON field name above) were
	// over budget; empty means the whole scan stayed within budget.
	Exceeded []string `json:"exceeded,omitempty"`
}

type BudgetDimension struct {
	Used  int64 `json:"used"`
	Limit int64 `json:"limit"`
}

type Analyzer interface {
	Metadata() AnalyzerMetadata
	Analyze(context.Context, AnalysisContext) ([]Finding, error)
}

// AnalyzerResult lets analyzers return diagnostics and narrow their own
// coverage state without turning a partially useful analysis into an error.
type AnalyzerResult struct {
	Findings    []Finding
	Diagnostics []Diagnostic
	Coverage    map[string]CoverageState
}

// ResultAnalyzer is an additive extension for analyzers that can complete
// with degraded coverage. Existing Analyzer implementations are unchanged.
type ResultAnalyzer interface {
	Analyzer
	AnalyzeResult(context.Context, AnalysisContext) (AnalyzerResult, error)
}

// CapabilityObservation records that an analyzer observed a skill artifact
// actually using a capability, independent of whether that usage was unsafe
// enough to also produce a Finding. Safe use of a declared capability (e.g.
// an argv-only subprocess call with a static allowlisted command) is
// legitimate and correctly produces no Finding — but it still must count as
// the capability having been observed, or contract verification cannot tell
// "safe declared use" apart from "never actually used" and will misreport
// the former as an overdeclared capability.
type CapabilityObservation struct {
	Capability string         `json:"capability" yaml:"capability"`
	Value      string         `json:"value,omitempty" yaml:"value,omitempty"`
	Location   Location       `json:"location" yaml:"location"`
	Analyzer   string         `json:"analyzer" yaml:"analyzer"`
	Evidence   map[string]any `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// ObservationAnalyzer is an additive capability an Analyzer may implement to
// report CapabilityObservations alongside its Findings in a single pass
// (avoiding a second parse/walk). Analyzers that do not implement it are
// unaffected; capability verification falls back to Finding-based inference
// for any capability no ObservationAnalyzer reports on.
type ObservationAnalyzer interface {
	AnalyzeCapabilities(context.Context, AnalysisContext) ([]Finding, []CapabilityObservation, error)
}

// DomainAnalyzer is an Analyzer that explicitly declares which taxonomy
// domain, subdomain, and controls it covers. The Registry uses this
// interface for domain-scoped operations and coverage reporting.
type DomainAnalyzer interface {
	Analyzer
	TaxonomyDomain() string
	TaxonomySubdomain() string
	ControlIDs() []string
}

type SemanticProvider interface {
	ID() string
	AnalyzeUntrusted(context.Context, SemanticRequest) ([]Finding, error)
}

type SemanticValidationMode string

const (
	SemanticValidationReview SemanticValidationMode = "review"
	SemanticValidationStrict SemanticValidationMode = "strict"
)

type SemanticValidationError struct {
	Index   int    `json:"index"`
	Message string `json:"message"`
}

type SemanticDiagnostics struct {
	Accepted int                       `json:"accepted"`
	Rejected int                       `json:"rejected"`
	Errors   []SemanticValidationError `json:"errors,omitempty"`
}

type SemanticAnalysis struct {
	Findings    []Finding           `json:"findings"`
	Diagnostics SemanticDiagnostics `json:"diagnostics"`
}

// DiagnosticSemanticProvider is an additive provider extension. Review-mode
// adapters use it to retain valid findings while reporting rejected output.
type DiagnosticSemanticProvider interface {
	SemanticProvider
	AnalyzeUntrustedDetailed(context.Context, SemanticRequest) (SemanticAnalysis, error)
}

type SemanticRequest struct {
	ArtifactDigest string            `json:"artifact_digest"`
	Files          map[string]string `json:"files"`
	Contract       *SkillContract    `json:"contract,omitempty"`
	Focus          string            `json:"focus,omitempty"`
	PriorFindings  []Finding         `json:"prior_findings,omitempty"`
	NoTools        bool              `json:"no_tools"`
}

type Vulnerability struct {
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Severity Severity `json:"severity"`
	Aliases  []string `json:"aliases,omitempty"`
}

type VulnerabilityProvider interface {
	ID() string
	Query(context.Context, string, string, string) ([]Vulnerability, error)
}

type VulnerabilityQuery struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
}

type BatchVulnerabilityProvider interface {
	VulnerabilityProvider
	QueryBatch(context.Context, []VulnerabilityQuery) ([][]Vulnerability, error)
}

type PackageReputation struct {
	Abandoned  bool
	LastUpdate time.Time
}

type PackageReputationProvider interface {
	Reputation(context.Context, string, string) (PackageReputation, error)
}

type ModelReputation struct {
	Publisher    string
	Downloads    int64
	LastUpdated  time.Time
	IsVerified   bool
	SensitiveOps bool
}

type ModelReputationProvider interface {
	ID() string
	Reputation(context.Context, string, string) (ModelReputation, error)
}

type DocumentTrust struct {
	Source      string
	Tenant      string
	Version     string
	LastUpdated time.Time
	IsVerified  bool
}

type DocumentTrustProvider interface {
	ID() string
	Trust(context.Context, string, string) (DocumentTrust, error)
}

type DomainReputation struct {
	Domain            string
	TLD               string
	Age               time.Duration
	IsSinkhole        bool
	IsKnownBad        bool
	IsNewlyRegistered bool
}

type DomainReputationProvider interface {
	ID() string
	Reputation(context.Context, string) (DomainReputation, error)
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

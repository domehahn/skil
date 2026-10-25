package completeness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/domehahn/skil/pkg/skil"
)

// ResolutionState defines the exactness of security identity resolution.
type ResolutionState string

const (
	StateExact          ResolutionState = "EXACT"
	StateBoundedSet     ResolutionState = "BOUNDED_SET"
	StatePartial        ResolutionState = "PARTIAL"
	StateRuntimeUnknown ResolutionState = "RUNTIME_UNKNOWN"
)

// ResolutionEvidence records how accurately an execution target identity was resolved at scan time.
type ResolutionEvidence struct {
	TargetSymbol string          `json:"target_symbol" yaml:"target_symbol"`
	TargetType   string          `json:"target_type" yaml:"target_type"` // e.g. "command", "builtin", "subcommand", "variable", "api"
	State        ResolutionState `json:"state" yaml:"state"`
	Reason       string          `json:"reason,omitempty" yaml:"reason,omitempty"`
	Candidates   []string        `json:"candidates,omitempty" yaml:"candidates,omitempty"`
}

// WorkLedger accounts for all scheduled analysis work and explicitly accounts for incomplete or excluded items.
// Invariant: Scheduled == Processed + Transformed + Skipped + Unsupported + BudgetExhausted + Failed
type WorkLedger struct {
	Scheduled       int `json:"scheduled" yaml:"scheduled"`
	Processed       int `json:"processed" yaml:"processed"`
	Transformed     int `json:"transformed" yaml:"transformed"`
	Skipped         int `json:"skipped" yaml:"skipped"`
	Unsupported     int `json:"unsupported" yaml:"unsupported"`
	BudgetExhausted int `json:"budget_exhausted" yaml:"budget_exhausted"`
	Failed          int `json:"failed" yaml:"failed"`
}

// IsValid checks the fundamental work accounting ledger invariant.
func (wl WorkLedger) IsValid() bool {
	return wl.Scheduled == (wl.Processed + wl.Transformed + wl.Skipped + wl.Unsupported + wl.BudgetExhausted + wl.Failed)
}

// IncompleteCount returns total work units that were not fully processed as standard exact targets.
func (wl WorkLedger) IncompleteCount() int {
	return wl.Transformed + wl.Skipped + wl.Unsupported + wl.BudgetExhausted + wl.Failed
}

// CompletionRatio returns the fraction of scheduled work successfully processed (0.0 - 1.0).
func (wl WorkLedger) CompletionRatio() float64 {
	if wl.Scheduled == 0 {
		return 1.0
	}
	return float64(wl.Processed) / float64(wl.Scheduled)
}

// ResultCommitProtocol ensures findings are committed prior to completion acknowledgement.
type ResultCommitProtocol struct {
	CommittedFindings  []string `json:"committed_findings" yaml:"committed_findings"`
	ResultReceived     bool     `json:"result_received" yaml:"result_received"`
	ResultValidated    bool     `json:"result_validated" yaml:"result_validated"`
	EvidenceCommitted  bool     `json:"evidence_committed" yaml:"evidence_committed"`
	CompletionReceived bool     `json:"completion_received" yaml:"completion_received"`
	Complete           bool     `json:"complete" yaml:"complete"`
	FinishTag          string   `json:"finish_tag" yaml:"finish_tag"` // e.g. "STOP", "TRUNCATED", "ERROR"
	CommitBeforeAck    bool     `json:"commit_before_ack" yaml:"commit_before_ack"`
	AnalysisIncomplete bool     `json:"analysis_incomplete" yaml:"analysis_incomplete"`
	TruncatedOutput    bool     `json:"truncated_output" yaml:"truncated_output"`
}

// NewResultCommitProtocol creates a new commit protocol instance.
func NewResultCommitProtocol() *ResultCommitProtocol {
	return &ResultCommitProtocol{
		CommittedFindings: []string{},
		CommitBeforeAck:   true,
	}
}

// CommitFinding adds a finding to the committed log prior to completion.
func (rcp *ResultCommitProtocol) CommitFinding(finding string) {
	rcp.ResultReceived = true
	rcp.ResultValidated = true
	rcp.CommittedFindings = append(rcp.CommittedFindings, finding)
	rcp.EvidenceCommitted = true
}

// Finalize sets the finish tag and determines if output was truncated or incomplete.
func (rcp *ResultCommitProtocol) Finalize(finishTag string) {
	rcp.FinishTag = finishTag
	rcp.CompletionReceived = finishTag != ""
	if finishTag != "STOP" && finishTag != "SUCCESS" {
		rcp.TruncatedOutput = true
		rcp.AnalysisIncomplete = true
	}
	rcp.Complete = rcp.CompletionReceived && !rcp.AnalysisIncomplete
}

// ObserverIdentity identifies and attests the scanner environment and version identity.
type ObserverIdentity struct {
	SkilVersion         string `json:"skil_version" yaml:"skil_version"`
	Commit              string `json:"commit" yaml:"commit"`
	BinaryDigest        string `json:"binary_digest" yaml:"binary_digest"`
	PolicyDigest        string `json:"policy_digest" yaml:"policy_digest"`
	AnalyzerSetDigest   string `json:"analyzer_set_digest" yaml:"analyzer_set_digest"`
	ConfigurationDigest string `json:"configuration_digest" yaml:"configuration_digest"`
	RuntimeMode         string `json:"runtime_mode" yaml:"runtime_mode"`
	AttestationIdentity string `json:"attestation_identity" yaml:"attestation_identity"`
	Digest              string `json:"digest" yaml:"digest"`
}

// BuildObserverIdentity constructs the observer identity with calculated digest.
func BuildObserverIdentity(skilVer, binDigest, polDigest, anaDigest, mode string) ObserverIdentity {
	return BuildObserverIdentityV2(skilVer, "unknown", binDigest, polDigest, anaDigest, "unknown", mode)
}

func BuildObserverIdentityV2(skilVer, commit, binDigest, polDigest, anaDigest, configDigest, mode string) ObserverIdentity {
	obs := ObserverIdentity{
		SkilVersion:         skilVer,
		Commit:              commit,
		BinaryDigest:        binDigest,
		PolicyDigest:        polDigest,
		AnalyzerSetDigest:   anaDigest,
		ConfigurationDigest: configDigest,
		RuntimeMode:         mode,
	}
	obs.AttestationIdentity = fmt.Sprintf("skil-observer:%s:%s", skilVer, mode)
	obs.Digest = obs.ComputeDigest()
	return obs
}

// RuntimeObserverIdentity derives only identities available to the running
// process. Unknown policy/analyzer identities remain explicitly unknown; they
// are never replaced with release-looking placeholder values.
func RuntimeObserverIdentity(policyDigest, analyzerDigest, mode string) ObserverIdentity {
	version, commit := "devel", "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && setting.Value != "" {
				commit = setting.Value
			}
		}
	}
	binaryDigest := "unknown"
	if executable, err := os.Executable(); err == nil {
		if data, readErr := os.ReadFile(executable); readErr == nil {
			sum := sha256.Sum256(data)
			binaryDigest = "sha256:" + hex.EncodeToString(sum[:])
		}
	}
	if policyDigest == "" {
		policyDigest = "unknown"
	}
	if analyzerDigest == "" {
		analyzerDigest = "unknown"
	}
	if mode == "" {
		mode = "unknown"
	}
	return BuildObserverIdentityV2(version, commit, binaryDigest, policyDigest, analyzerDigest, "unknown", mode)
}

// ComputeDigest generates a deterministic hash of the observer identity fields.
func (obs ObserverIdentity) ComputeDigest() string {
	h := sha256.New()
	h.Write([]byte(obs.SkilVersion + "|" + obs.Commit + "|" + obs.BinaryDigest + "|" + obs.PolicyDigest + "|" + obs.AnalyzerSetDigest + "|" + obs.ConfigurationDigest + "|" + obs.RuntimeMode))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// CompletenessClassification categorizes the ground truth completeness level.
type CompletenessClassification string

const (
	ClassFull          CompletenessClassification = "FULL"
	ClassPartial       CompletenessClassification = "PARTIAL"
	ClassOpaque        CompletenessClassification = "OPAQUE"
	ClassUnsupported   CompletenessClassification = "UNSUPPORTED"
	ClassBudgetLimited CompletenessClassification = "BUDGET_LIMITED"
)

// BenchmarkResult records a single benchmark evaluation case.
type BenchmarkResult struct {
	FixtureName    string                     `json:"fixture_name"`
	ExpectedClass  CompletenessClassification `json:"expected_class"`
	ActualClass    CompletenessClassification `json:"actual_class"`
	FalseCompleted bool                       `json:"false_completed"`
}

// CompletenessAccuracyBenchmark measures scan classification accuracy against ground truth.
type CompletenessAccuracyBenchmark struct{}

// Classify determines the completeness classification from a work ledger and resolution set.
func (b CompletenessAccuracyBenchmark) Classify(ledger WorkLedger, resolutions []ResolutionEvidence, incomplete bool) CompletenessClassification {
	if ledger.BudgetExhausted > 0 {
		return ClassBudgetLimited
	}
	if ledger.Unsupported > 0 && ledger.Processed == 0 {
		return ClassUnsupported
	}
	if incomplete {
		return ClassPartial
	}

	opaqueCount := 0
	partialCount := 0
	for _, res := range resolutions {
		if res.State == StateRuntimeUnknown {
			opaqueCount++
		} else if res.State == StatePartial || res.State == StateBoundedSet {
			partialCount++
		}
	}

	if opaqueCount > 0 && opaqueCount >= len(resolutions)/2 {
		return ClassOpaque
	}
	if opaqueCount > 0 || partialCount > 0 || ledger.IncompleteCount() > 0 {
		return ClassPartial
	}

	return ClassFull
}

// CalculateFalseCompleteRate calculates the False Complete Rate (FCR) across benchmark results.
func (b CompletenessAccuracyBenchmark) CalculateFalseCompleteRate(results []BenchmarkResult) float64 {
	if len(results) == 0 {
		return 0.0
	}
	falseCompletes := 0
	for _, r := range results {
		// False complete occurs when actual is reported as FULL, but expected was PARTIAL/OPAQUE/UNSUPPORTED/BUDGET_LIMITED
		if r.ActualClass == ClassFull && r.ExpectedClass != ClassFull {
			falseCompletes++
		}
	}
	return float64(falseCompletes) / float64(len(results))
}

// CompletenessReport aggregates resolution completeness findings, work ledger, and observer attestation.
type CompletenessReport struct {
	SkillPath          string                     `json:"skill_path" yaml:"skill_path"`
	Observer           ObserverIdentity           `json:"observer" yaml:"observer"`
	WorkLedger         WorkLedger                 `json:"work_ledger" yaml:"work_ledger"`
	CommitProtocol     ResultCommitProtocol       `json:"commit_protocol" yaml:"commit_protocol"`
	Resolutions        []ResolutionEvidence       `json:"resolutions" yaml:"resolutions"`
	Classification     CompletenessClassification `json:"classification" yaml:"classification"`
	FalseCompleteRisk  bool                       `json:"false_complete_risk" yaml:"false_complete_risk"`
	GroundTruthSummary string                     `json:"ground_truth_summary" yaml:"ground_truth_summary"`
}

// AnalyzeCompleteness performs full completeness and work accounting analysis on a skill path.
func AnalyzeCompleteness(skillPath string, findings []skil.Finding) (*CompletenessReport, error) {
	_, err := os.Stat(skillPath)
	if err != nil {
		return nil, fmt.Errorf("unable to access skill path %s: %w", skillPath, err)
	}

	obs := RuntimeObserverIdentity("unknown", "unknown", "CLI")

	rcp := NewResultCommitProtocol()
	for _, f := range findings {
		rcp.CommitFinding(fmt.Sprintf("%s: %s", f.ID, f.Message))
	}
	rcp.Finalize("STOP")
	// This compatibility API receives findings but no scanner inspection
	// ledger. It cannot truthfully claim completed repository analysis.
	rcp.AnalysisIncomplete = true
	rcp.Complete = false

	// Collect resolution evidence and build work ledger from file scan inspection
	resolutions := []ResolutionEvidence{}
	scheduled := len(findings) + 1
	processed := len(findings)
	transformed := 0
	skipped := 1 // unavailable scanner inspection ledger
	unsupported := 0
	budgetExhausted := 0
	failed := 0

	// Dynamic target checks
	hasDynamicWrapper := false
	for _, f := range findings {
		if f.Category == "DYNAMIC_EXECUTION" || f.RuleID == "DYNAMIC_EXEC" {
			hasDynamicWrapper = true
			resolutions = append(resolutions, ResolutionEvidence{
				TargetSymbol: "command",
				TargetType:   "shell_builtin",
				State:        StatePartial,
				Reason:       "Target binary is bound dynamically at runtime",
			})
			transformed++
			processed--
		}
	}

	if !hasDynamicWrapper {
		resolutions = append(resolutions, ResolutionEvidence{
			TargetSymbol: "main_execution_surface",
			TargetType:   "static_entry",
			State:        StateRuntimeUnknown,
			Reason:       "No scanner inspection ledger was supplied",
		})
	}

	ledger := WorkLedger{
		Scheduled:       scheduled,
		Processed:       processed,
		Transformed:     transformed,
		Skipped:         skipped,
		Unsupported:     unsupported,
		BudgetExhausted: budgetExhausted,
		Failed:          failed,
	}

	bm := CompletenessAccuracyBenchmark{}
	class := bm.Classify(ledger, resolutions, rcp.AnalysisIncomplete)

	return &CompletenessReport{
		SkillPath:          skillPath,
		Observer:           obs,
		WorkLedger:         ledger,
		CommitProtocol:     *rcp,
		Resolutions:        resolutions,
		Classification:     class,
		FalseCompleteRisk:  class == ClassFull && ledger.IncompleteCount() > 0,
		GroundTruthSummary: fmt.Sprintf("Classification=%s, CompletionRatio=%.2f", class, ledger.CompletionRatio()),
	}, nil
}

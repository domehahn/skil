package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/derived"
	"github.com/domehahn/skil/pkg/skil"
)

type Registry struct {
	analyzers []skil.Analyzer
}

func DefaultRegistry(vuln skil.VulnerabilityProvider) *Registry {
	items := []skil.Analyzer{
		NewPattern(), NewPythonAST(), NewStructuredAST(), NewTaint(), NewDependency(vuln), NewMCP(), NewBoundary(), NewUnicode(),
		NewLocalSemantic(), NewModelArtifact(), NewSecret(), NewBuild(), NewIdentity(), NewLateral(), NewAsset(),
		NewSkill(), NewToolCapability(), NewDataDataset(), NewRAGContext(), NewMultiAgent(), NewAuditEvidence(), NewPolicyEnforcement(),
		NewHiddenInstruction(), NewTrigger(), NewResourceConfig(), NewCredentialFlow(), NewDataClassification(), NewPyC(), NewRubyAST(), NewAgentExecutionSurface(),
		NewIntentDivergence(), NewJailbreak(), NewDependencySource(),
	}
	return &Registry{analyzers: items}
}

func (r *Registry) Register(a skil.Analyzer) error {
	meta := a.Metadata()
	if meta.ID == "" || meta.Version == "" {
		return fmt.Errorf("analyzer id and version are required")
	}
	for _, existing := range r.analyzers {
		if existing.Metadata().ID == meta.ID {
			return fmt.Errorf("analyzer %q already registered", meta.ID)
		}
	}
	r.analyzers = append(r.analyzers, a)
	return nil
}

func (r *Registry) Metadata() []skil.AnalyzerMetadata {
	out := make([]skil.AnalyzerMetadata, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		out = append(out, a.Metadata())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Domains returns the unique set of domain identifiers registered.
func (r *Registry) Domains() []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range r.analyzers {
		d := a.Metadata().Domain
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// AnalyzersByDomain returns analyzers whose domain matches the given filter.
func (r *Registry) AnalyzersByDomain(domain string) []skil.Analyzer {
	var out []skil.Analyzer
	for _, a := range r.analyzers {
		if a.Metadata().Domain == domain {
			out = append(out, a)
		}
	}
	return out
}

// DomainCoverage returns domain -> completed/not_requested for all registered domains.
func (r *Registry) DomainCoverage() map[string]skil.CoverageState {
	out := map[string]skil.CoverageState{}
	for _, a := range r.analyzers {
		d := a.Metadata().Domain
		if d == "" {
			continue
		}
		if _, exists := out[d]; !exists {
			out[d] = skil.CoverageNotRequested
		}
	}
	return out
}

func (r *Registry) Scan(ctx context.Context, ac skil.AnalysisContext) (skil.ScanResult, error) {
	nativeRules := nativeRuleIDs()
	budget := skil.DefaultAnalysisBudget()
	if ac.Budget != nil {
		budget = *ac.Budget
		defaults := skil.DefaultAnalysisBudget()
		// These dimensions are additive. Zero in callers compiled against the
		// earlier struct means "unspecified", not an unbounded reconstruction.
		if budget.MaxDerivedViews == 0 {
			budget.MaxDerivedViews = defaults.MaxDerivedViews
		}
		if budget.MaxDerivedDepth == 0 {
			budget.MaxDerivedDepth = defaults.MaxDerivedDepth
		}
		if budget.MaxDerivedBytes == 0 {
			budget.MaxDerivedBytes = defaults.MaxDerivedBytes
		}
	}
	wallStart := time.Now()
	budgetCtx, cancelBudget := context.WithTimeout(ctx, budget.MaxWallTime)
	defer cancelBudget()
	result := skil.ScanResult{
		SchemaVersion: "1.0.0", Artifact: ac.Artifact, Findings: []skil.Finding{},
		Coverage: map[string]skil.CoverageState{
			"pattern": skil.CoverageNotRequested, "ast": skil.CoverageNotRequested,
			"static-code": skil.CoverageNotRequested,
			"taint":       skil.CoverageNotRequested, "dependency": skil.CoverageNotRequested,
			"vulnerability": skil.CoverageNotRequested, "reputation": skil.CoverageNotRequested,
			"mcp": skil.CoverageNotRequested, "malware": skil.CoverageNotRequested,
			"semantic": skil.CoverageNotRequested, "semantic-provider": skil.CoverageNotRequested,
			"behavioral": skil.CoverageNotRun, "trigger": skil.CoverageNotRequested,
			"resource-config": skil.CoverageNotRequested, "taint-output": skil.CoverageNotRequested,
			"analysis-budget": skil.CoverageCompleted,
			"derived-views":   skil.CoverageCompleted,
		},
		Scanners: []string{"skil"},
	}
	// Byte ceilings are knowable before any analyzer starts. Fail closed at
	// that boundary instead of doing expensive work and only reporting the
	// overrun afterward.
	preflight := computeBudgetUsage(ac.Artifact, budget, result, wallStart, false)
	if len(preflight.Exceeded) > 0 {
		result.Budget = preflight
		result.Coverage["analysis-budget"] = skil.CoverageDegraded
		result.Status = skil.StatusWarn
		result.Diagnostics = append(result.Diagnostics, skil.Diagnostic{
			Component: "analysis-budget", Level: "warning",
			Message: fmt.Sprintf("analysis not started because the artifact exceeds: %s", strings.Join(preflight.Exceeded, ", ")),
		})
		return result, nil
	}
	if len(ac.Artifact.LoadDiagnostics) > 0 {
		result.Diagnostics = append(result.Diagnostics, ac.Artifact.LoadDiagnostics...)
	}
	derivedResult := derived.Build(budgetCtx, ac.Artifact, derived.Budget{
		MaxViews: budget.MaxDerivedViews, MaxDepth: budget.MaxDerivedDepth, MaxBytes: budget.MaxDerivedBytes,
	})
	result.DerivedViews = derivedSummary(derivedResult)
	if !derivedResult.Complete {
		result.Coverage["derived-views"] = skil.CoverageDegraded
		for _, limitation := range derivedResult.Limitations {
			result.Diagnostics = append(result.Diagnostics, skil.Diagnostic{Component: "derived-views", Level: "warning", Message: limitation})
		}
	}
	domainFilter := ac.DomainFilter
	inspectionBudgetStopped := false
	filterSet := map[string]bool{}
	for _, d := range domainFilter {
		filterSet[d] = true
	}
	if len(domainFilter) > 0 {
		for _, d := range r.Domains() {
			if filterSet[d] {
				result.Coverage["domain:"+d] = skil.CoverageNotRequested
			}
		}
	}
	for _, a := range r.analyzers {
		meta := a.Metadata()
		if budget.MaxFindings > 0 && len(result.Findings) > budget.MaxFindings ||
			budget.MaxInspectionEvents > 0 && len(result.Inspection) >= budget.MaxInspectionEvents {
			inspectionBudgetStopped = budget.MaxInspectionEvents > 0 && len(result.Inspection) >= budget.MaxInspectionEvents
			result.Inspection = append(result.Inspection, skil.InspectionWorkItem{
				Analyzer: meta.ID, Version: meta.Version, File: "*", Outcome: skil.InspectionSkipped,
				Reason: "analysis budget exhausted before analyzer start",
			})
			break
		}
		if budget.MaxInspectionEvents > 0 && len(result.Inspection)+len(ac.Artifact.Files) > budget.MaxInspectionEvents {
			inspectionBudgetStopped = true
			result.Inspection = append(result.Inspection, skil.InspectionWorkItem{
				Analyzer: meta.ID, Version: meta.Version, File: "*", Outcome: skil.InspectionSkipped,
				Reason: "analysis budget: inspection event limit would be exceeded",
			})
			break
		}
		if len(domainFilter) > 0 && meta.Domain != "" && !filterSet[meta.Domain] {
			continue
		}
		if ctx.Err() == nil && budgetCtx.Err() != nil {
			// The wall-time budget is already exhausted: skip this
			// analyzer entirely rather than starting work that would
			// only be interrupted partway through, and record it as
			// explicitly skipped (not out_of_scope, not failed) so the
			// reason is unambiguous in the inspection ledger.
			for _, file := range ac.Artifact.Files {
				result.Inspection = append(result.Inspection, skil.InspectionWorkItem{
					Analyzer: meta.ID, Version: meta.Version, File: file.Path,
					Outcome: skil.InspectionSkipped, Reason: "analysis budget: wall-time limit exceeded",
				})
			}
			continue
		}
		start := len(result.Inspection)
		for _, file := range ac.Artifact.Files {
			item := skil.InspectionWorkItem{
				Analyzer: meta.ID, Version: meta.Version, File: file.Path,
				Outcome: skil.InspectionOutOfScope, Reason: "file type is outside analyzer scope",
			}
			if analyzerApplies(meta, file) {
				item.Outcome = skil.InspectionCompleted
				item.Reason = ""
			}
			result.Inspection = append(result.Inspection, item)
		}
		var findings []skil.Finding
		var observations []skil.CapabilityObservation
		var diagnostics []skil.Diagnostic
		var coverageOverride map[string]skil.CoverageState
		var err error
		findings, observations, diagnostics, coverageOverride, err = invokeAnalyzer(budgetCtx, a, ac)
		if err != nil {
			if ctx.Err() == nil && budgetCtx.Err() != nil {
				// The analyzer failed specifically because the budget's
				// wall-time deadline (not the caller's own ctx) expired
				// mid-analysis — a soft degradation the overall scan
				// still completes and reports (Status raised to at least
				// WARN below), not a hard Scan() failure. A caller-level
				// ctx cancellation independent of the budget still falls
				// through to the hard-failure path beneath this branch.
				for index := start; index < len(result.Inspection); index++ {
					if result.Inspection[index].Outcome == skil.InspectionCompleted {
						result.Inspection[index].Outcome = skil.InspectionSkipped
						result.Inspection[index].Reason = "analysis budget: wall-time limit exceeded mid-analysis"
					}
				}
				continue
			}
			for index := start; index < len(result.Inspection); index++ {
				if result.Inspection[index].Outcome == skil.InspectionCompleted {
					result.Inspection[index].Outcome = skil.InspectionFailed
					result.Inspection[index].Reason = err.Error()
				}
			}
			result.Completeness = summarizeInspection(result.Inspection)
			return result, fmt.Errorf("%s analyzer: %w", meta.ID, err)
		}
		for _, finding := range findings {
			if strings.HasPrefix(finding.RuleID, "SKIL-") && !nativeRuleKnown(nativeRules, finding.RuleID) {
				return result, fmt.Errorf("%s analyzer emitted unpublished native rule %q", meta.ID, finding.RuleID)
			}
		}
		result.Findings = append(result.Findings, findings...)
		result.Observations = append(result.Observations, observations...)
		result.Diagnostics = append(result.Diagnostics, diagnostics...)
		analyzeDerivedViews(budgetCtx, a, ac, derivedResult.Views, nativeRules, budget, &result)
		if source, ok := a.(interface{ Diagnostics() []skil.Diagnostic }); ok {
			result.Diagnostics = append(result.Diagnostics, source.Diagnostics()...)
		}
		for index := start; index < len(result.Inspection); index++ {
			for _, finding := range findings {
				if finding.Location.File == result.Inspection[index].File {
					result.Inspection[index].Findings++
				}
			}
		}
		for _, typ := range meta.AnalysisTypes {
			result.Coverage[typ] = skil.CoverageCompleted
		}
		for typ, state := range coverageOverride {
			result.Coverage[typ] = state
		}
		if len(domainFilter) > 0 && meta.Domain != "" && filterSet[meta.Domain] {
			result.Coverage["domain:"+meta.Domain] = skil.CoverageCompleted
		}
	}
	if ac.Contract == nil {
		if advisory, ok := missingCapabilityDeclaration(result.Findings); ok {
			result.Findings = append(result.Findings, advisory)
		}
	}
	result.Findings = append(result.Findings, correlateThreatChains(result.Findings, result.Observations)...)
	dependencies, err := dependencyIdentities(ac.Artifact, result.Observations)
	if err != nil {
		return result, fmt.Errorf("build dependency identities: %w", err)
	}
	result.Dependencies = dependencies
	result.Completeness = summarizeInspection(result.Inspection)
	for _, file := range ac.Artifact.Files {
		result.Analyzability = append(result.Analyzability, classifyAnalyzability(file, ac.Artifact.Files))
	}
	result.Analyzable = summarizeAnalyzability(result.Analyzability)
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
	result.Maximum, result.RiskScore, result.Status = Risk(result.Findings, result.Coverage)
	wallExceeded := (ctx.Err() == nil && budgetCtx.Err() != nil) || (budget.MaxWallTime > 0 && time.Since(wallStart) >= budget.MaxWallTime) || (budget.MaxWallTime <= 0)
	result.Budget = computeBudgetUsage(ac.Artifact, budget, result, wallStart, wallExceeded)
	if inspectionBudgetStopped && !slices.Contains(result.Budget.Exceeded, "inspection_events") {
		result.Budget.Exceeded = append(result.Budget.Exceeded, "inspection_events")
	}
	if len(result.Budget.Exceeded) > 0 {
		result.Coverage["analysis-budget"] = skil.CoverageDegraded
		if result.Status == skil.StatusPass {
			result.Status = skil.StatusWarn
		}
		result.Diagnostics = append(result.Diagnostics, skil.Diagnostic{
			Component: "analysis-budget", Level: "warning",
			Message: fmt.Sprintf("scan exceeded its analysis budget in: %s", strings.Join(result.Budget.Exceeded, ", ")),
		})
	}
	return result, nil
}

func invokeAnalyzer(ctx context.Context, analyzer skil.Analyzer, ac skil.AnalysisContext) ([]skil.Finding, []skil.CapabilityObservation, []skil.Diagnostic, map[string]skil.CoverageState, error) {
	if resultAnalyzer, ok := analyzer.(skil.ResultAnalyzer); ok {
		result, err := resultAnalyzer.AnalyzeResult(ctx, ac)
		return result.Findings, nil, result.Diagnostics, result.Coverage, err
	}
	if observationAnalyzer, ok := analyzer.(skil.ObservationAnalyzer); ok {
		findings, observations, err := observationAnalyzer.AnalyzeCapabilities(ctx, ac)
		return findings, observations, nil, nil, err
	}
	findings, err := analyzer.Analyze(ctx, ac)
	return findings, nil, nil, nil, err
}

func derivedSummary(result derived.Result) *skil.DerivedViewSummary {
	views := make([]skil.DerivedViewEvidence, len(result.Views))
	for index := range result.Views {
		views[index] = result.Views[index].Evidence
	}
	return &skil.DerivedViewSummary{
		Views: views, Complete: result.Complete, Bytes: result.Bytes, MaxDepth: result.MaxDepth,
		Exceeded: append([]string(nil), result.Exceeded...), Limitations: append([]string(nil), result.Limitations...),
	}
}

func analyzeDerivedViews(ctx context.Context, analyzer skil.Analyzer, ac skil.AnalysisContext, views []derived.View, nativeRules []string, budget skil.AnalysisBudget, result *skil.ScanResult) {
	meta := analyzer.Metadata()
	if meta.ID == "builtin.obfuscation" || slices.Contains(meta.AnalysisTypes, "semantic-provider") {
		return
	}
	originals := map[string]skil.File{}
	for _, file := range ac.Artifact.Files {
		originals[file.Path] = file
	}
	for _, view := range views {
		if ctx.Err() != nil {
			degradeDerived(result, view.Evidence.SourcePath+": derived analyzer execution cancelled")
			return
		}
		original, ok := originals[view.Evidence.SourcePath]
		if !ok {
			degradeDerived(result, view.Evidence.SourcePath+": original source for derived view is unavailable")
			continue
		}
		derivedFile := original
		derivedFile.Data = view.Data
		derivedFile.SHA256 = view.Evidence.Digest
		if !analyzerApplies(meta, derivedFile) {
			continue
		}
		if budget.MaxInspectionEvents > 0 && len(result.Inspection) >= budget.MaxInspectionEvents {
			degradeDerived(result, "derived analyzer inspection budget exhausted")
			if result.DerivedViews != nil && !slices.Contains(result.DerivedViews.Exceeded, "inspection_events") {
				result.DerivedViews.Exceeded = append(result.DerivedViews.Exceeded, "inspection_events")
			}
			return
		}
		item := skil.InspectionWorkItem{
			Analyzer: meta.ID, Version: meta.Version, File: original.Path + "#" + view.Evidence.ID,
			Outcome: skil.InspectionCompleted, Reason: "derived security view",
		}
		derivedArtifact := ac.Artifact
		derivedArtifact.Files = []skil.File{derivedFile}
		derivedContext := ac
		derivedContext.Artifact = derivedArtifact
		findings, observations, diagnostics, coverage, err := invokeAnalyzer(ctx, analyzer, derivedContext)
		if err != nil {
			item.Outcome = skil.InspectionFailed
			item.Reason = "derived security view: " + err.Error()
			result.Inspection = append(result.Inspection, item)
			degradeDerived(result, fmt.Sprintf("%s: %s could not analyze %s: %v", original.Path, meta.ID, view.Evidence.ID, err))
			continue
		}
		for _, state := range coverage {
			if state == skil.CoverageDegraded || state == skil.CoverageNotAvailable {
				degradeDerived(result, fmt.Sprintf("%s: %s reported degraded derived-view coverage", original.Path, meta.ID))
			}
		}
		for _, diagnostic := range diagnostics {
			diagnostic.Component = "derived-views/" + diagnostic.Component
			diagnostic.Message = view.Evidence.ID + ": " + diagnostic.Message
			result.Diagnostics = append(result.Diagnostics, diagnostic)
		}
		for _, finding := range findings {
			if finding.Location.File != original.Path || strings.HasPrefix(finding.RuleID, "SKIL-") && !nativeRuleKnown(nativeRules, finding.RuleID) {
				continue
			}
			annotated, ok := annotateDerivedFinding(finding, original, view)
			if !ok {
				continue
			}
			result.Findings = append(result.Findings, annotated)
			item.Findings++
		}
		for _, observation := range observations {
			if observation.Location.File != original.Path {
				continue
			}
			annotated, ok := annotateDerivedObservation(observation, original, view)
			if ok {
				result.Observations = append(result.Observations, annotated)
			}
		}
		result.Inspection = append(result.Inspection, item)
	}
}

func annotateDerivedFinding(finding skil.Finding, original skil.File, view derived.View) (skil.Finding, bool) {
	start, end := lineByteRange(view.Data, finding.Location.StartLine, finding.Location.EndLine)
	span, changed := view.OriginalSpan(start, end)
	if !changed {
		return skil.Finding{}, false
	}
	if finding.Evidence == nil {
		finding.Evidence = map[string]any{}
	}
	finding.Evidence["derived_view_id"] = view.Evidence.ID
	finding.Evidence["derived_view_digest"] = view.Evidence.Digest
	finding.Evidence["derived_source_digest"] = view.Evidence.SourceDigest
	finding.Evidence["derived_transformations"] = view.Evidence.Transformations
	finding.Evidence["derived_start_line"] = finding.Location.StartLine
	finding.Evidence["derived_end_line"] = finding.Location.EndLine
	finding.Evidence["original_start_offset"] = span.Start
	finding.Evidence["original_end_offset"] = span.End
	finding.Location.StartLine = lineForOffset(original.Data, span.Start)
	finding.Location.EndLine = lineForOffset(original.Data, max(span.Start, span.End-1))
	finding.Fingerprint = fingerprint(finding.Fingerprint, view.Evidence.ID, strconv.Itoa(span.Start), strconv.Itoa(span.End))
	finding.ID = "F-" + strings.ToUpper(finding.Fingerprint[:12])
	return finding, true
}

func annotateDerivedObservation(observation skil.CapabilityObservation, original skil.File, view derived.View) (skil.CapabilityObservation, bool) {
	start, end := lineByteRange(view.Data, observation.Location.StartLine, observation.Location.EndLine)
	span, changed := view.OriginalSpan(start, end)
	if !changed {
		return skil.CapabilityObservation{}, false
	}
	if observation.Evidence == nil {
		observation.Evidence = map[string]any{}
	}
	observation.Evidence["derived_view_id"] = view.Evidence.ID
	observation.Evidence["derived_view_digest"] = view.Evidence.Digest
	observation.Evidence["derived_source_digest"] = view.Evidence.SourceDigest
	observation.Evidence["derived_transformations"] = view.Evidence.Transformations
	observation.Evidence["original_start_offset"] = span.Start
	observation.Evidence["original_end_offset"] = span.End
	observation.Location.StartLine = lineForOffset(original.Data, span.Start)
	observation.Location.EndLine = lineForOffset(original.Data, max(span.Start, span.End-1))
	return observation, true
}

func lineByteRange(data []byte, startLine, endLine int) (int, int) {
	if startLine <= 0 {
		return 0, len(data)
	}
	if endLine < startLine {
		endLine = startLine
	}
	line, start, end := 1, 0, len(data)
	for index, value := range data {
		if line == startLine {
			start = index
			break
		}
		if value == '\n' {
			line++
		}
	}
	line = startLine
	for index := start; index < len(data); index++ {
		if data[index] == '\n' {
			if line >= endLine {
				end = index
				break
			}
			line++
		}
	}
	if end <= start {
		end = min(len(data), start+1)
	}
	return start, end
}

func lineForOffset(data []byte, offset int) int {
	if offset > len(data) {
		offset = len(data)
	}
	return 1 + strings.Count(string(data[:offset]), "\n")
}

func degradeDerived(result *skil.ScanResult, limitation string) {
	result.Coverage["derived-views"] = skil.CoverageDegraded
	result.Diagnostics = append(result.Diagnostics, skil.Diagnostic{Component: "derived-views", Level: "warning", Message: limitation})
	if result.DerivedViews != nil {
		result.DerivedViews.Complete = false
		if !slices.Contains(result.DerivedViews.Limitations, limitation) {
			result.DerivedViews.Limitations = append(result.DerivedViews.Limitations, limitation)
			sort.Strings(result.DerivedViews.Limitations)
		}
	}
}

func dependencyIdentities(artifact skil.Artifact, observations []skil.CapabilityObservation) ([]skil.DependencyIdentity, error) {
	records, err := DiscoverDependencies(artifact)
	if err != nil {
		return nil, err
	}
	type source struct{ url, kind, pkg string }
	sources := map[string][]source{}
	for _, observation := range observations {
		if observation.Capability != "dependency.source" {
			continue
		}
		ecosystem, _ := observation.Evidence["ecosystem"].(string)
		kind, _ := observation.Evidence["source_kind"].(string)
		pkg, _ := observation.Evidence["package"].(string)
		sources[normalizeDependencyEcosystem(ecosystem)] = append(sources[normalizeDependencyEcosystem(ecosystem)], source{observation.Value, kind, pkg})
	}
	fileDigests := map[string]string{}
	for _, file := range artifact.Files {
		digest := file.SHA256
		if digest == "" {
			sum := sha256.Sum256(file.Data)
			digest = hex.EncodeToString(sum[:])
		}
		fileDigests[file.Path] = digest
	}
	var identities []skil.DependencyIdentity
	seen := map[string]bool{}
	for _, record := range records {
		ecosystem := normalizeDependencyEcosystem(record.Ecosystem)
		candidates := sources[ecosystem]
		if record.URL != "" {
			candidates = []source{{url: record.URL, kind: "direct"}}
		}
		if len(candidates) == 0 {
			if official := officialDependencySource(ecosystem); official != "" {
				candidates = []source{{url: official, kind: "official"}}
			} else {
				candidates = []source{{kind: "unknown"}}
			}
		}
		for _, candidate := range candidates {
			if candidate.pkg != "" && candidate.pkg != record.Name {
				continue
			}
			kind := candidate.kind
			if kind == "" {
				kind = "registry"
			}
			identity := skil.DependencyIdentity{
				Ecosystem: ecosystem, Package: record.Name, Version: record.Version,
				SourceKind: kind, SourceURL: candidate.url, ManifestDigest: fileDigests[record.File],
				Evidence: skil.Location{File: record.File, StartLine: record.Line, EndLine: record.Line},
			}
			key := strings.Join([]string{identity.Ecosystem, identity.Package, identity.Version, identity.SourceKind, identity.SourceURL, identity.ManifestDigest, identity.Evidence.File, strconv.Itoa(identity.Evidence.StartLine)}, "\x00")
			if !seen[key] {
				seen[key] = true
				identities = append(identities, identity)
			}
		}
	}
	sort.Slice(identities, func(i, j int) bool {
		a, b := identities[i], identities[j]
		return a.Ecosystem+"\x00"+a.Package+"\x00"+a.Version+"\x00"+a.SourceURL+"\x00"+a.Evidence.File < b.Ecosystem+"\x00"+b.Package+"\x00"+b.Version+"\x00"+b.SourceURL+"\x00"+b.Evidence.File
	})
	return identities, nil
}

func normalizeDependencyEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "pypi", "python":
		return "pypi"
	case "crates.io", "cargo":
		return "cargo"
	case "npm", "node":
		return "npm"
	case "maven":
		return "maven"
	case "go":
		return "go"
	case "rubygems", "ruby":
		return "rubygems"
	default:
		return strings.ToLower(ecosystem)
	}
}

func officialDependencySource(ecosystem string) string {
	return map[string]string{
		"npm": "https://registry.npmjs.org/", "pypi": "https://pypi.org/simple/",
		"cargo": "https://index.crates.io/", "maven": "https://repo.maven.apache.org/maven2/",
		"go": "https://proxy.golang.org/", "rubygems": "https://rubygems.org/",
	}[ecosystem]
}

// computeBudgetUsage measures what one completed (or budget-interrupted)
// scan consumed against budget, dimension by dimension. wallTimeExceeded
// is passed in explicitly (rather than re-derived here) since it depends
// on distinguishing the injected budget deadline from the caller's own
// ctx, which only Scan's own two context values can tell apart.
func computeBudgetUsage(artifact skil.Artifact, budget skil.AnalysisBudget, result skil.ScanResult, wallStart time.Time, wallTimeExceeded bool) skil.AnalysisBudgetUsage {
	var rawBytes, expandedBytes int64
	for _, file := range artifact.Files {
		if file.ContainerDepth > 0 {
			expandedBytes += int64(len(file.Data))
		} else {
			rawBytes += int64(len(file.Data))
		}
	}
	elapsed := time.Since(wallStart)
	usage := skil.AnalysisBudgetUsage{
		RawBytes:         skil.BudgetDimension{Used: rawBytes, Limit: budget.MaxRawBytes},
		ExpandedBytes:    skil.BudgetDimension{Used: expandedBytes, Limit: budget.MaxExpandedBytes},
		Findings:         skil.BudgetDimension{Used: int64(len(result.Findings)), Limit: int64(budget.MaxFindings)},
		InspectionEvents: skil.BudgetDimension{Used: int64(len(result.Inspection)), Limit: int64(budget.MaxInspectionEvents)},
		DerivedViews:     skil.BudgetDimension{Limit: int64(budget.MaxDerivedViews)},
		DerivedDepth:     skil.BudgetDimension{Limit: int64(budget.MaxDerivedDepth)},
		DerivedBytes:     skil.BudgetDimension{Limit: budget.MaxDerivedBytes},
		WallTime:         skil.BudgetDimension{Used: elapsed.Milliseconds(), Limit: budget.MaxWallTime.Milliseconds()},
	}
	if result.DerivedViews != nil {
		usage.DerivedViews.Used = int64(len(result.DerivedViews.Views))
		usage.DerivedDepth.Used = int64(result.DerivedViews.MaxDepth)
		usage.DerivedBytes.Used = result.DerivedViews.Bytes
		usage.Exceeded = append(usage.Exceeded, result.DerivedViews.Exceeded...)
	}
	if usage.RawBytes.Limit > 0 && usage.RawBytes.Used > usage.RawBytes.Limit {
		usage.Exceeded = append(usage.Exceeded, "raw_bytes")
	}
	if usage.ExpandedBytes.Limit > 0 && usage.ExpandedBytes.Used > usage.ExpandedBytes.Limit {
		usage.Exceeded = append(usage.Exceeded, "expanded_bytes")
	}
	if usage.Findings.Limit > 0 && usage.Findings.Used > usage.Findings.Limit {
		usage.Exceeded = append(usage.Exceeded, "findings")
	}
	if usage.InspectionEvents.Limit > 0 && usage.InspectionEvents.Used > usage.InspectionEvents.Limit {
		usage.Exceeded = append(usage.Exceeded, "inspection_events")
	}
	if usage.DerivedViews.Limit > 0 && usage.DerivedViews.Used > usage.DerivedViews.Limit && !slices.Contains(usage.Exceeded, "derived_views") {
		usage.Exceeded = append(usage.Exceeded, "derived_views")
	}
	if usage.DerivedDepth.Limit > 0 && usage.DerivedDepth.Used > usage.DerivedDepth.Limit && !slices.Contains(usage.Exceeded, "derived_depth") {
		usage.Exceeded = append(usage.Exceeded, "derived_depth")
	}
	if usage.DerivedBytes.Limit > 0 && usage.DerivedBytes.Used > usage.DerivedBytes.Limit && !slices.Contains(usage.Exceeded, "derived_bytes") {
		usage.Exceeded = append(usage.Exceeded, "derived_bytes")
	}
	if wallTimeExceeded {
		usage.Exceeded = append(usage.Exceeded, "wall_time")
	}
	sort.Strings(usage.Exceeded)
	return usage
}

func makeFinding(rule RulePattern, file skil.File, line int, matched string) skil.Finding {
	fp := fingerprint(rule.Rule.ID, file.Path, strconv.Itoa(line), normalizeEvidence(matched))
	return skil.Finding{
		ID: "F-" + strings.ToUpper(fp[:12]), RuleID: rule.Rule.ID, Category: rule.Rule.Category,
		Severity: rule.Rule.Severity, Confidence: rule.Confidence, Title: rule.Rule.Title,
		Message: rule.Rule.Description, Description: rule.Rule.Description,
		Location: skil.Location{File: file.Path, StartLine: line, EndLine: line},
		Evidence: map[string]any{"match": truncate(matched, 160)}, Remediation: rule.Rule.Remediation,
		References: rule.Rule.References, Fingerprint: fp,
		ContextDisposition: "confirmed",
	}
}

func missingCapabilityDeclaration(findings []skil.Finding) (skil.Finding, bool) {
	capabilities := map[string]bool{}
	var location skil.Location
	for _, finding := range findings {
		if finding.Suppressed || finding.Confidence < .8 {
			continue
		}
		capability, _ := finding.Evidence["capability"].(string)
		if capability == "" {
			capability = capabilityForRule(finding.RuleID)
		}
		if capability == "" {
			continue
		}
		capabilities[capability] = true
		if location.File == "" {
			location = finding.Location
		}
	}
	if len(capabilities) == 0 {
		return skil.Finding{}, false
	}
	observed := make([]string, 0, len(capabilities))
	for capability := range capabilities {
		observed = append(observed, capability)
	}
	sort.Strings(observed)
	rule := RulePattern{Rule: skil.Rule{
		ID: "SKIL-CAP-DECLARATION-MISSING", Title: "Capability declaration missing",
		Category: "contract-conformance", Severity: skil.SeverityMedium,
		Description: "Security-sensitive behavior was observed, but no skill contract declares its capability boundary.",
		Analysis:    "verification", Remediation: "Add a skill contract with narrowly scoped capabilities and rerun validation.",
	}, Confidence: .95}
	finding := makeFinding(rule, skil.File{Path: location.File}, location.StartLine, "no skill contract")
	finding.Location = location
	finding.Evidence = map[string]any{"observed_capabilities": observed}
	return finding, true
}

func capabilityForRule(ruleID string) string {
	switch ruleID {
	case "SKIL-NET-001", "SKIL-INTENT-EXTERNAL-TRANSFER", "SKIL-TAINT-NETWORK", "SKIL-TAINT-PRIVILEGED-CONTEXT":
		return "network.outbound"
	case "SKIL-FS-001", "SKIL-TAINT-FILESYSTEM-WRITE":
		return "filesystem.write"
	case "SKIL-SEC-001":
		return "secrets.read"
	case "SKIL-PY-002", "SKIL-SH-001", "SKIL-SH-002", "SKIL-SH-003", "SKIL-SH-004",
		"SKIL-JS-001", "SKIL-INTENT-COMMAND", "SKIL-TAINT-EXECUTION", "SKIL-TAINT-OUTPUT-EXECUTION",
		"SKIL-AGENT-HOOK-001", "SKIL-AGENT-HOOK-002", "SKIL-AGENT-HOOK-003", "SKIL-AGENT-PERM-001", "SKIL-AGENT-PERM-002",
		"SKIL-INTENT-DIVERGENCE", "SKIL-JAILBREAK-001", "SKIL-JAILBREAK-002", "SKIL-JAILBREAK-003",
		"SKIL-DEP-SOURCE-OVERRIDE", "SKIL-DEP-SOURCE-INSECURE", "SKIL-DEP-SOURCE-REDIRECT", "SKIL-RAG-003":
		return "commands.execute"
	case "SKIL-RAG-001", "SKIL-RAG-002", "SKIL-MEMORY-PERSISTENCE-001", "SKIL-RAG-INGESTION-001":
		return "persistence"
	case "SKIL-TAINT-OUTPUT-CROSS-AGENT", "SKIL-DEP-MALICIOUS":
		return "multi-agent"
	case "SKIL-PI-HIDDEN-COMMENT", "SKIL-PI-MD-HIDDEN-COMMENT", "SKIL-PI-MD-SUSPICIOUS-COMMENT", "SKIL-MEMORY-FALSE-RESET", "SKIL-MEMORY-FALSE-REPRESENTATION":
		return "instruction-integrity"
	case "SKIL-RESOURCE-UNLIMITED", "SKIL-RESOURCE-TIMEOUT", "SKIL-RESOURCE-UNBOUNDED-LOOP":
		return "resource-boundary"
	default:
		return ""
	}
}

func analyzerApplies(meta skil.AnalyzerMetadata, file skil.File) bool {
	ext := strings.ToLower(extension(file.Path))
	base := strings.ToLower(file.Path)
	if slash := strings.LastIndex(base, "/"); slash >= 0 {
		base = base[slash+1:]
	}
	for _, supported := range meta.SupportedTypes {
		supported = strings.ToLower(strings.TrimPrefix(supported, "."))
		switch supported {
		case "*":
			return true
		case "text":
			if isText(file) {
				return true
			}
		case "markdown":
			if ext == "md" || ext == "markdown" {
				return true
			}
		default:
			if ext == supported || base == supported || strings.HasSuffix(base, supported) {
				return true
			}
		}
	}
	return false
}

func summarizeInspection(items []skil.InspectionWorkItem) skil.InspectionSummary {
	summary := skil.InspectionSummary{Total: len(items)}
	for _, item := range items {
		switch item.Outcome {
		case skil.InspectionCompleted:
			summary.Applicable++
			summary.Completed++
		case skil.InspectionSkipped:
			summary.Applicable++
			summary.Skipped++
		case skil.InspectionFailed:
			summary.Applicable++
			summary.Failed++
		case skil.InspectionOutOfScope:
			summary.OutOfScope++
		}
	}
	if summary.Applicable == 0 {
		summary.Completeness = 1
	} else {
		summary.Completeness = float64(summary.Completed) / float64(summary.Applicable)
	}
	return summary
}

func nativeRuleIDs() []string {
	builtin := BuiltinRules()
	out := make([]string, 0, len(builtin))
	for _, rule := range builtin {
		out = append(out, rule.ID)
	}
	return out
}

func nativeRuleKnown(rules []string, id string) bool {
	for _, rule := range rules {
		if rule == id || strings.HasSuffix(rule, "*") && strings.HasPrefix(id, strings.TrimSuffix(rule, "*")) {
			return true
		}
	}
	return false
}

func Verdict(maximum skil.Severity, score int, coverage map[string]skil.CoverageState) skil.Verdict {
	if maximum == skil.SeverityCritical || maximum == skil.SeverityHigh || score >= 40 {
		return skil.VerdictBlock
	}
	if maximum == skil.SeverityMedium || score >= 10 || hasDegradedCoverage(coverage) ||
		coverage["ast"] != skil.CoverageCompleted || coverage["taint"] != skil.CoverageCompleted {
		return skil.VerdictReview
	}
	return skil.VerdictClear
}

func hasDegradedCoverage(coverage map[string]skil.CoverageState) bool {
	for _, state := range coverage {
		if state == skil.CoverageDegraded || state == skil.CoverageNotAvailable {
			return true
		}
	}
	return false
}

func Risk(findings []skil.Finding, coverage map[string]skil.CoverageState) (skil.Severity, int, skil.Status) {
	weights := map[skil.Severity]int{
		skil.SeverityInfo: 0, skil.SeverityLow: 3, skil.SeverityMedium: 8,
		skil.SeverityHigh: 18, skil.SeverityCritical: 30,
	}
	ranks := map[skil.Severity]int{
		skil.SeverityInfo: 0, skil.SeverityLow: 1, skil.SeverityMedium: 2,
		skil.SeverityHigh: 3, skil.SeverityCritical: 4,
	}
	max := skil.SeverityInfo
	score := 0.0
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		score += float64(weights[f.Severity]) * f.Confidence
		if f.Category == "contract-conformance" {
			score += 10
		}
		if ranks[f.Severity] > ranks[max] {
			max = f.Severity
		}
	}
	if coverage["ast"] != skil.CoverageCompleted || coverage["taint"] != skil.CoverageCompleted {
		score += 5
	}
	if score > 100 {
		score = 100
	}
	status := skil.StatusPass
	if max == skil.SeverityMedium {
		status = skil.StatusWarn
	} else if ranks[max] >= ranks[skil.SeverityHigh] {
		status = skil.StatusFail
	}
	return max, int(score + 0.5), status
}

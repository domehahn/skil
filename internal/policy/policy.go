package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/evidence"
	"github.com/domehahn/skil/internal/importer"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/internal/verification"
	"github.com/domehahn/skil/pkg/skil"
	"github.com/domehahn/skil/schemas"
	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version                       int      `json:"version" yaml:"version"`
	MaximumSeverity               string   `json:"maximum_severity" yaml:"maximum_severity"`
	RequiredAnalysis              []string `json:"required_analysis,omitempty" yaml:"required_analysis,omitempty"`
	MinimumInspectionCompleteness float64  `json:"minimum_inspection_completeness,omitempty" yaml:"minimum_inspection_completeness,omitempty"`
	// MinimumAnalyzability and DenyOpaqueExecutableContent gate on
	// skil.AnalyzabilitySummary/AnalyzabilityRecord (see
	// internal/analyzer's classifyAnalyzability) — a narrower question
	// than inspection completeness: not "did every applicable analyzer
	// run" but "was the file's actual content visible to analysis at
	// all". A pure-binary artifact with no text-scoped analyzer to skip
	// can score 100% inspection completeness while being completely
	// opaque; these two checks are how a policy catches that case
	// specifically.
	MinimumAnalyzability            float64             `json:"minimum_analyzability,omitempty" yaml:"minimum_analyzability,omitempty"`
	DenyOpaqueExecutableContent     bool                `json:"deny_opaque_executable_content,omitempty" yaml:"deny_opaque_executable_content,omitempty"`
	ForbiddenCapabilities           []string            `json:"forbidden_capabilities,omitempty" yaml:"forbidden_capabilities,omitempty"`
	AllowedCapabilities             []string            `json:"allowed_capabilities,omitempty" yaml:"allowed_capabilities,omitempty"`
	ForbiddenRules                  []string            `json:"forbidden_rules,omitempty" yaml:"forbidden_rules,omitempty"`
	MinimumScans                    int                 `json:"minimum_scans,omitempty" yaml:"minimum_scans,omitempty"`
	RequiredScanners                []string            `json:"required_scanners,omitempty" yaml:"required_scanners,omitempty"`
	TrustedScanners                 []string            `json:"trusted_scanners,omitempty" yaml:"trusted_scanners,omitempty"`
	TrustedScannerKeys              map[string][]string `json:"trusted_scanner_keys,omitempty" yaml:"trusted_scanner_keys,omitempty"`
	TrustedSigners                  map[string]string   `json:"trusted_signers,omitempty" yaml:"trusted_signers,omitempty"`
	TrustedBuilders                 []string            `json:"trusted_builders,omitempty" yaml:"trusted_builders,omitempty"`
	TrustedBuilderKeys              map[string][]string `json:"trusted_builder_keys,omitempty" yaml:"trusted_builder_keys,omitempty"`
	AllowedRepositories             []string            `json:"allowed_repositories,omitempty" yaml:"allowed_repositories,omitempty"`
	AllowedRegistries               []string            `json:"allowed_registries,omitempty" yaml:"allowed_registries,omitempty"`
	MaxAttestationAge               string              `json:"max_attestation_age,omitempty" yaml:"max_attestation_age,omitempty"`
	RequireDigest                   bool                `json:"require_artifact_digest" yaml:"require_artifact_digest"`
	RequireSignature                bool                `json:"require_signature" yaml:"require_signature"`
	RequireProvenance               bool                `json:"require_provenance" yaml:"require_provenance"`
	RequireProvenanceSignature      bool                `json:"require_provenance_signature" yaml:"require_provenance_signature"`
	MaxEvidenceAge                  string              `json:"max_evidence_age,omitempty" yaml:"max_evidence_age,omitempty"`
	RequireBehavioralEvaluation     bool                `json:"require_behavioral_evaluation,omitempty" yaml:"require_behavioral_evaluation,omitempty"`
	RequireContainmentEvaluation    bool                `json:"require_containment_evaluation,omitempty" yaml:"require_containment_evaluation,omitempty"`
	RequireRuntimeEnforcement       bool                `json:"require_runtime_enforcement,omitempty" yaml:"require_runtime_enforcement,omitempty"`
	RequireNativeIsolation          bool                `json:"require_native_isolation,omitempty" yaml:"require_native_isolation,omitempty"`
	MaximumContainmentViolationRate *float64            `json:"maximum_containment_violation_rate,omitempty" yaml:"maximum_containment_violation_rate,omitempty"`
	RequireZeroForbiddenSideEffects bool                `json:"require_zero_forbidden_side_effects,omitempty" yaml:"require_zero_forbidden_side_effects,omitempty"`
	RequiredDomains                 []string            `json:"required_domains,omitempty" yaml:"required_domains,omitempty"`
	AllowedDomains                  []string            `json:"allowed_domains,omitempty" yaml:"allowed_domains,omitempty"`
	ForbiddenDomains                []string            `json:"forbidden_domains,omitempty" yaml:"forbidden_domains,omitempty"`
	// RevokedSignerKeyIDs/RevokedArtifactDigests/RevokedSkills implement
	// revocation as a first-class primitive: once a publisher's signing key,
	// a specific artifact digest, or a skill (name or name@version) appears
	// here, every install, update, and re-evaluation is denied regardless
	// of how strong its existing signature, attestation, or provenance is —
	// revocation always overrides prior trust rather than merely failing to
	// add new trust.
	RevokedSignerKeyIDs    []string `json:"revoked_signer_key_ids,omitempty" yaml:"revoked_signer_key_ids,omitempty"`
	RevokedArtifactDigests []string `json:"revoked_artifact_digests,omitempty" yaml:"revoked_artifact_digests,omitempty"`
	RevokedSkills          []string `json:"revoked_skills,omitempty" yaml:"revoked_skills,omitempty"`
}
type Violation struct {
	Rule     string `json:"rule" yaml:"rule"`
	Expected any    `json:"expected" yaml:"expected"`
	Observed any    `json:"observed" yaml:"observed"`
	Message  string `json:"message" yaml:"message"`
}
type Result struct {
	Decision   string      `json:"decision" yaml:"decision"`
	Violations []Violation `json:"violations" yaml:"violations"`
}
type Input struct {
	Scan             skil.ScanResult
	Contract         *skil.SkillContract
	Attestation      *skil.Attestation
	Provenance       *skil.Provenance
	PackageStatement *skil.PackageStatement
	ExternalEvidence []skil.EvidenceBundle
	Eval             *skil.EvalResult
}

func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	if err := schemas.ValidateYAML("policy-v1.schema.json", data); err != nil {
		return Policy{}, err
	}
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	if p.Version != 1 {
		return p, fmt.Errorf("unsupported policy version %d", p.Version)
	}
	if p.MaximumSeverity == "" {
		p.MaximumSeverity = "HIGH"
	}
	return p, nil
}

func Check(p Policy, in Input) Result {
	result := Result{Decision: "ALLOW", Violations: []Violation{}}
	add := func(rule string, expected, observed any, message string) {
		result.Violations = append(result.Violations, Violation{rule, expected, observed, message})
	}
	checkRevocation(p, in, &result)
	if severityRank(in.Scan.Maximum) > severityRank(skil.Severity(strings.ToUpper(p.MaximumSeverity))) {
		add("maximum-severity", strings.ToUpper(p.MaximumSeverity), in.Scan.Maximum, "maximum finding severity exceeds policy")
	}
	for _, required := range p.RequiredAnalysis {
		if in.Scan.Coverage[required] != skil.CoverageCompleted {
			add("required-analysis", required, in.Scan.Coverage[required], "required analysis was not completed")
		}
	}
	if p.MinimumInspectionCompleteness > 0 &&
		in.Scan.Completeness.Completeness < p.MinimumInspectionCompleteness {
		add("inspection-completeness", p.MinimumInspectionCompleteness, in.Scan.Completeness.Completeness,
			"applicable inspection work did not meet the required completion ratio")
	}
	if p.MinimumAnalyzability > 0 && in.Scan.Analyzable.Coverage < p.MinimumAnalyzability {
		add("minimum-analyzability", p.MinimumAnalyzability, in.Scan.Analyzable.Coverage,
			"too much of the artifact's content was opaque to analysis")
	}
	if p.DenyOpaqueExecutableContent {
		for _, record := range in.Scan.Analyzability {
			if record.State == skil.AnalyzabilityOpaque && (record.BinaryKind != "" || record.Executable) {
				add("deny-opaque-executable-content", false, record.Path,
					"artifact contains executable or archive content skil could not inspect: "+record.Reason)
			}
		}
	}
	for _, rule := range p.ForbiddenRules {
		for _, f := range in.Scan.Findings {
			if f.RuleID == rule && !f.Suppressed {
				add("forbidden-rule", rule, f.RuleID, "forbidden rule produced a finding")
			}
		}
	}
	for _, bundle := range in.ExternalEvidence {
		if err := verifyExternalEvidence(bundle, in.Scan.Artifact, p); err != nil {
			add("external-evidence", "valid signed evidence bound to the artifact", err.Error(), "external scanner evidence verification failed")
			continue
		}
		if !contains(in.Scan.Scanners, bundle.Evidence.Producer) {
			in.Scan.Scanners = append(in.Scan.Scanners, bundle.Evidence.Producer)
		}
	}
	if p.MinimumScans > len(in.Scan.Scanners) {
		add("minimum-scans", p.MinimumScans, len(in.Scan.Scanners), "insufficient independent scanner evidence")
	}
	for _, required := range p.RequiredScanners {
		if !contains(in.Scan.Scanners, required) {
			add("required-scanner", required, in.Scan.Scanners, "required scanner evidence is missing")
		}
	}
	for _, scanner := range in.Scan.Scanners {
		if len(p.TrustedScanners) > 0 && !contains(p.TrustedScanners, scanner) {
			add("trusted-scanner", p.TrustedScanners, scanner, "evidence came from an untrusted scanner")
		}
	}
	if p.RequireDigest && in.Scan.Artifact.SubjectDigest() == "" {
		add("artifact-digest", true, false, "artifact digest is required")
	}
	checkEvaluation(p, in, &result)
	if p.RequireSignature && (in.PackageStatement == nil || in.PackageStatement.Signature == nil) {
		add("package-signature", true, false, "a detached signature over the package blob is required")
	} else if in.PackageStatement != nil {
		if in.PackageStatement.PackageSHA256 != in.Scan.Artifact.PackageDigest ||
			in.PackageStatement.ContentManifestSHA256 != in.Scan.Artifact.Digest {
			add("package-signature-subject", []string{in.Scan.Artifact.PackageDigest, in.Scan.Artifact.Digest},
				[]string{in.PackageStatement.PackageSHA256, in.PackageStatement.ContentManifestSHA256},
				"package signature subject does not match both package and content digests")
		} else if err := signing.VerifyPackageStatement(*in.PackageStatement, p.TrustedSigners); err != nil {
			add("package-signature", "cryptographically valid signature from a trusted key", err.Error(), "package signature verification failed")
		}
		if in.Contract != nil && (in.PackageStatement.Name != in.Contract.Skill.Name ||
			in.PackageStatement.VersionName != in.Contract.Skill.Version) {
			add("package-identity", []string{in.Contract.Skill.Name, in.Contract.Skill.Version},
				[]string{in.PackageStatement.Name, in.PackageStatement.VersionName}, "signed package identity does not match the contract")
		}
	}
	if in.Attestation != nil && in.Attestation.Signature != nil {
		if err := signing.VerifyAttestation(*in.Attestation, p.TrustedSigners); err != nil {
			add("attestation-signature", "cryptographically valid signature from a trusted key", err.Error(), "attestation signature verification failed")
		}
	}
	if p.RequireProvenance && in.Provenance == nil {
		add("provenance", true, false, "provenance is required")
	}
	if in.Provenance != nil {
		statement, err := signing.ParseProvenance(*in.Provenance)
		if err != nil {
			add("provenance-format", "DSSE in-toto Statement v1", err.Error(), "provenance format is invalid")
		} else {
			validateProvenance(p, *in.Provenance, statement, in.Scan.Artifact, &result)
		}
		if p.RequireProvenanceSignature && len(in.Provenance.Signatures) == 0 {
			add("provenance-signature", true, false, "signed provenance is required")
		}
	}
	if in.Attestation != nil {
		if err := VerifyAttestation(*in.Attestation, in.Scan.Artifact, p.MaxAttestationAge); err != nil {
			add("attestation", "valid and current", err.Error(), "attestation verification failed")
		}
		for _, item := range in.Attestation.Evidence {
			if item.Type == "security-scan" && item.Producer == "skil" && item.PayloadDigest != evidence.FindingsDigest(in.Scan.Findings) {
				add("evidence-payload", evidence.FindingsDigest(in.Scan.Findings), item.PayloadDigest, "native scan evidence payload does not match the current findings")
			}
			if item.Type == "security-scan" && item.Producer == "skil" && item.InspectionDigest != "" &&
				item.InspectionDigest != evidence.InspectionDigest(in.Scan.Inspection) {
				add("inspection-evidence", evidence.InspectionDigest(in.Scan.Inspection), item.InspectionDigest,
					"attested inspection ledger does not match the current scan")
			}
			if (item.Type == "behavioral-eval" || item.Type == "containment-eval") && item.Producer == "skil" {
				if in.Eval == nil {
					add("evaluation-evidence-payload", "matching evaluation result", "missing",
						"attested evaluation evidence cannot be verified without --eval-result")
				} else if item.PayloadDigest != evidence.EvalDigest(*in.Eval) {
					add("evaluation-evidence-payload", evidence.EvalDigest(*in.Eval), item.PayloadDigest,
						"attested evaluation payload does not match the supplied evaluation result")
				}
			}
		}
		if in.Attestation.Result.Status != in.Scan.Status ||
			in.Attestation.Result.Verdict != in.Scan.Verdict ||
			in.Attestation.Result.MaximumSeverity != in.Scan.Maximum ||
			in.Attestation.Result.RiskScore != in.Scan.RiskScore {
			add("attestation-result", in.Scan, in.Attestation.Result, "attested verdict does not match the current scan")
		}
	}
	if len(p.AllowedRegistries) > 0 && !hasAllowedPrefix(in.Scan.Artifact.Source, p.AllowedRegistries) {
		add("allowed-registry", p.AllowedRegistries, in.Scan.Artifact.Source, "artifact source is not from an allowed registry")
	}
	observed := verification.Infer(in.Scan.Findings, in.Scan.Observations)
	for _, denied := range p.ForbiddenCapabilities {
		if capabilityObserved(denied, observed) {
			add("forbidden-capability", denied, true, "forbidden capability was observed")
		}
	}
	if len(p.AllowedCapabilities) > 0 {
		for _, capability := range observedNames(observed) {
			if !contains(p.AllowedCapabilities, capability) {
				add("allowed-capability", p.AllowedCapabilities, capability, "observed capability is outside the allowlist")
			}
		}
	}
	for _, required := range p.RequiredDomains {
		if in.Scan.Coverage["domain:"+required] != skil.CoverageCompleted {
			add("required-domain", required, in.Scan.Coverage["domain:"+required], "required domain analysis was not completed")
		}
	}
	if len(p.AllowedDomains) > 0 {
		for domain, state := range in.Scan.Coverage {
			if !strings.HasPrefix(domain, "domain:") {
				continue
			}
			d := strings.TrimPrefix(domain, "domain:")
			if state == skil.CoverageCompleted && !contains(p.AllowedDomains, d) {
				add("allowed-domain", p.AllowedDomains, d, "domain analysis was completed but domain is outside the allowlist")
			}
		}
	}
	if len(p.ForbiddenDomains) > 0 {
		for domain, state := range in.Scan.Coverage {
			if !strings.HasPrefix(domain, "domain:") {
				continue
			}
			d := strings.TrimPrefix(domain, "domain:")
			if state == skil.CoverageCompleted && contains(p.ForbiddenDomains, d) {
				add("forbidden-domain", d, true, "forbidden domain analysis produced coverage")
			}
		}
	}
	if len(result.Violations) > 0 {
		result.Decision = "DENY"
	}
	return result
}

func checkRevocation(p Policy, in Input, result *Result) {
	add := func(rule string, expected, observed any, message string) {
		result.Violations = append(result.Violations, Violation{rule, expected, observed, message})
	}
	if digest := in.Scan.Artifact.SubjectDigest(); digest != "" && contains(p.RevokedArtifactDigests, digest) {
		add("revoked-artifact", "not revoked", digest, "this exact artifact digest has been revoked")
	}
	if in.Contract != nil {
		name := in.Contract.Skill.Name
		versioned := name + "@" + in.Contract.Skill.Version
		if contains(p.RevokedSkills, name) || contains(p.RevokedSkills, versioned) {
			add("revoked-skill", "not revoked", versioned, "this skill has been revoked")
		}
	}
	if in.PackageStatement != nil && in.PackageStatement.Signature != nil &&
		contains(p.RevokedSignerKeyIDs, in.PackageStatement.Signature.KeyID) {
		add("revoked-signer", "not revoked", in.PackageStatement.Signature.KeyID, "the package signer's key has been revoked")
	}
	if in.Attestation != nil && in.Attestation.Signature != nil &&
		contains(p.RevokedSignerKeyIDs, in.Attestation.Signature.KeyID) {
		add("revoked-signer", "not revoked", in.Attestation.Signature.KeyID, "the attestation signer's key has been revoked")
	}
}

func checkEvaluation(p Policy, in Input, result *Result) {
	add := func(rule string, expected, observed any, message string) {
		result.Violations = append(result.Violations, Violation{rule, expected, observed, message})
	}
	required := p.RequireBehavioralEvaluation || p.RequireContainmentEvaluation ||
		p.RequireRuntimeEnforcement || p.RequireNativeIsolation ||
		p.MaximumContainmentViolationRate != nil || p.RequireZeroForbiddenSideEffects
	if in.Eval == nil {
		if required {
			add("evaluation-evidence", true, false, "required behavioral evaluation result is missing")
		}
		return
	}
	evaluation := in.Eval
	if evaluation.ArtifactDigest != in.Scan.Artifact.SubjectDigest() {
		add("evaluation-subject", in.Scan.Artifact.SubjectDigest(), evaluation.ArtifactDigest,
			"evaluation result is not bound to the scanned artifact")
	}
	if p.RequireBehavioralEvaluation && evaluation.Coverage.Behavioral != skil.CoverageCompleted {
		add("behavioral-evaluation", skil.CoverageCompleted, evaluation.Coverage.Behavioral,
			"behavioral evaluation was not completed")
	}
	if p.RequireContainmentEvaluation && evaluation.Coverage.Containment != skil.CoverageCompleted {
		add("containment-evaluation", skil.CoverageCompleted, evaluation.Coverage.Containment,
			"containment evaluation was not completed")
	}
	if p.RequireRuntimeEnforcement && evaluation.Coverage.Enforcement != skil.CoverageCompleted {
		add("runtime-enforcement", skil.CoverageCompleted, evaluation.Coverage.Enforcement,
			"runtime enforcement was not completed")
	}
	if p.RequireNativeIsolation && evaluation.Coverage.NativeIsolation != skil.CoverageCompleted {
		add("native-isolation", skil.CoverageCompleted, evaluation.Coverage.NativeIsolation,
			"native isolation was not completed")
	}
	if p.MaximumContainmentViolationRate != nil {
		observed := 1.0
		if evaluation.Metrics.ContainmentComplianceRate != nil {
			observed = 1 - *evaluation.Metrics.ContainmentComplianceRate
		}
		if observed > *p.MaximumContainmentViolationRate {
			add("containment-violation-rate", *p.MaximumContainmentViolationRate, observed,
				"containment violation rate exceeds policy")
		}
	}
	if p.RequireZeroForbiddenSideEffects {
		count := 0
		for _, run := range evaluation.Runs {
			for _, violation := range run.Trace.ContainmentViolations {
				if violation.SideEffect {
					count++
				}
			}
		}
		if count > 0 {
			add("forbidden-side-effects", 0, count, "evaluation recorded external or mutating side effects")
		}
	}
}

func verifyExternalEvidence(bundle skil.EvidenceBundle, artifact skil.Artifact, p Policy) error {
	if bundle.Version != 1 {
		return fmt.Errorf("unsupported evidence bundle version %d", bundle.Version)
	}
	if bundle.Evidence.Type != "external-security-scan" {
		return fmt.Errorf("unsupported external evidence type %q", bundle.Evidence.Type)
	}
	if bundle.Evidence.SubjectDigest != artifact.SubjectDigest() {
		return errors.New("external evidence subject does not match artifact")
	}
	if bundle.Evidence.Producer == "" || len(bundle.Evidence.PayloadDigest) != 64 || len(bundle.Payload) == 0 {
		return errors.New("external evidence producer or payload digest is incomplete")
	}
	payload := sha256.Sum256(bundle.Payload)
	if hex.EncodeToString(payload[:]) != bundle.Evidence.PayloadDigest {
		return errors.New("external evidence payload digest does not match embedded payload")
	}
	normalized, err := (importer.SARIF{}).Import(context.Background(), bundle.Payload, artifact)
	if err != nil {
		return fmt.Errorf("validate embedded SARIF: %w", err)
	}
	if len(normalized) != 1 || normalized[0].Producer != bundle.Evidence.Producer ||
		normalized[0].ProducerVer != bundle.Evidence.ProducerVer ||
		normalized[0].Result != bundle.Evidence.Result {
		return errors.New("external evidence verdict or producer does not match the embedded SARIF results")
	}
	if bundle.Evidence.Result.Findings < 0 || bundle.Evidence.Result.Status == "" {
		return errors.New("external evidence verdict is incomplete")
	}
	if bundle.Evidence.Result.Status == skil.StatusFail ||
		severityRank(bundle.Evidence.Result.MaximumSeverity) > severityRank(skil.Severity(strings.ToUpper(p.MaximumSeverity))) {
		return fmt.Errorf("external scanner verdict is %s with maximum severity %s",
			bundle.Evidence.Result.Status, bundle.Evidence.Result.MaximumSeverity)
	}
	if len(p.TrustedScanners) > 0 && !contains(p.TrustedScanners, bundle.Evidence.Producer) {
		return fmt.Errorf("external scanner %q is not trusted", bundle.Evidence.Producer)
	}
	if p.MaxEvidenceAge != "" {
		duration, err := parseAge(p.MaxEvidenceAge)
		if err != nil {
			return err
		}
		if time.Since(bundle.Evidence.Timestamp) > duration {
			return errors.New("external evidence is stale")
		}
	}
	if err := signing.VerifyEvidenceBundle(bundle, p.TrustedSigners); err != nil {
		return err
	}
	if bundle.Signature == nil || !contains(p.TrustedScannerKeys[bundle.Evidence.Producer], bundle.Signature.KeyID) {
		return fmt.Errorf("signing key is not bound to scanner %q", bundle.Evidence.Producer)
	}
	return nil
}

func validateProvenance(p Policy, provenance skil.Provenance, statement skil.InTotoStatement, artifact skil.Artifact, result *Result) {
	add := func(rule string, expected, observed any, message string) {
		result.Violations = append(result.Violations, Violation{rule, expected, observed, message})
	}
	if statement.Type != "https://in-toto.io/Statement/v1" {
		add("provenance-statement", "https://in-toto.io/Statement/v1", statement.Type, "provenance is not an in-toto Statement v1")
	}
	if statement.PredicateType != "https://slsa.dev/provenance/v1" {
		add("provenance-predicate", "https://slsa.dev/provenance/v1", statement.PredicateType, "provenance predicate type is not supported")
	}
	if len(statement.Subject) != 1 || statement.Subject[0].Digest["sha256"] != artifact.SubjectDigest() {
		add("provenance-digest", artifact.SubjectDigest(), statement.Subject, "provenance subject does not match artifact")
	}
	builder := statement.Predicate.RunDetails.Builder.ID
	params := statement.Predicate.BuildDefinition.ExternalParameters
	repository, commit := params["source_repository"], params["source_commit"]
	if strings.TrimSpace(repository) == "" || strings.TrimSpace(commit) == "" || strings.TrimSpace(builder) == "" ||
		statement.Predicate.RunDetails.Metadata.FinishedOn.IsZero() {
		add("provenance-completeness", "source repository, commit, builder, and timestamp", statement.Predicate, "provenance metadata is incomplete")
	}
	if len(p.TrustedBuilders) > 0 && !contains(p.TrustedBuilders, builder) {
		add("trusted-builder", p.TrustedBuilders, builder, "provenance builder is not trusted")
	}
	if len(p.AllowedRepositories) > 0 && !contains(p.AllowedRepositories, repository) {
		add("allowed-repository", p.AllowedRepositories, repository, "source repository is not allowed")
	}
	if statement.Predicate.RunDetails.Metadata.FinishedOn.After(time.Now().Add(5 * time.Minute)) {
		add("provenance-timestamp", "not in the future", statement.Predicate.RunDetails.Metadata.FinishedOn, "provenance build timestamp is in the future")
	}
	if err := signing.VerifyProvenance(provenance, p.TrustedSigners); err != nil {
		add("provenance-signature", "cryptographically valid DSSE signature", err.Error(), "provenance signature verification failed")
		return
	}
	allowedKeys := p.TrustedBuilderKeys[builder]
	bound := false
	for _, signature := range provenance.Signatures {
		if contains(allowedKeys, signature.KeyID) {
			bound = true
		}
	}
	if !bound {
		add("builder-key-binding", allowedKeys, provenance.Signatures, "DSSE signing key is not bound to the asserted builder")
	}
}

func hasAllowedPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if value == prefix || strings.HasPrefix(value, strings.TrimRight(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

func VerifyAttestation(a skil.Attestation, artifact skil.Artifact, maxAge string) error {
	if a.Subject.SHA256 != artifact.SubjectDigest() {
		return errors.New("attestation subject digest does not match artifact")
	}
	if maxAge != "" {
		duration, err := parseAge(maxAge)
		if err != nil {
			return fmt.Errorf("invalid max age: %w", err)
		}
		if time.Since(a.Timestamp) > duration {
			return errors.New("attestation is stale")
		}
	}
	for _, e := range a.Evidence {
		if e.SubjectDigest != artifact.SubjectDigest() {
			return errors.New("evidence subject digest does not match artifact")
		}
	}
	return nil
}

func parseAge(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err == nil {
		return duration, nil
	}
	if strings.HasSuffix(value, "d") {
		days := strings.TrimSuffix(value, "d")
		duration, err = time.ParseDuration(days + "h")
		if err == nil {
			return duration * 24, nil
		}
	}
	return 0, fmt.Errorf("invalid age %q: %w", value, err)
}

func severityRank(s skil.Severity) int {
	return map[skil.Severity]int{skil.SeverityInfo: 0, skil.SeverityLow: 1, skil.SeverityMedium: 2, skil.SeverityHigh: 3, skil.SeverityCritical: 4}[s]
}
func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
func capabilityObserved(name string, o skil.ObservedCapabilities) bool {
	switch name {
	case "network.outbound":
		return o.NetworkOutbound
	case "commands.execute":
		return o.CommandsExecute
	case "filesystem.write":
		return o.FilesystemWrite
	case "filesystem.delete":
		return o.FilesystemDelete
	case "secrets.read":
		return o.SecretsRead
	case "persistence":
		return o.Persistence
	case "external_side_effects":
		return o.ExternalSideEffects
	default:
		return false
	}
}

func observedNames(o skil.ObservedCapabilities) []string {
	names := []string{}
	for _, name := range []string{"network.outbound", "commands.execute", "filesystem.write", "filesystem.delete", "secrets.read", "persistence", "external_side_effects"} {
		if capabilityObserved(name, o) {
			names = append(names, name)
		}
	}
	return names
}

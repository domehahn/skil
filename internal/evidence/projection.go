package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// SecurityProjection is the lossless, security-critical subset that every
// evidence transformation and handoff must preserve.
type SecurityProjection struct {
	EvidenceID       string             `json:"evidence_id" yaml:"evidence_id"`
	FindingID        string             `json:"finding_id" yaml:"finding_id"`
	RuleID           string             `json:"rule_id" yaml:"rule_id"`
	ArtifactIdentity string             `json:"artifact_identity" yaml:"artifact_identity"`
	Location         skil.Location      `json:"location" yaml:"location"`
	Severity         skil.Severity      `json:"severity" yaml:"severity"`
	Confidence       float64            `json:"confidence" yaml:"confidence"`
	Verification     skil.EvidenceState `json:"verification_state" yaml:"verification_state"`
	Provenance       []string           `json:"provenance" yaml:"provenance"`
	Classification   string             `json:"classification" yaml:"classification"`
}

func ProjectFinding(f skil.Finding, artifact string, state skil.EvidenceState, provenance []string) (SecurityProjection, error) {
	if f.ID == "" || f.RuleID == "" || artifact == "" || f.Location.File == "" {
		return SecurityProjection{}, errors.New("security projection requires stable finding, rule, artifact, and location identities")
	}
	provenance = append([]string(nil), provenance...)
	sort.Strings(provenance)
	return SecurityProjection{EvidenceID: "finding:" + f.ID, FindingID: f.ID, RuleID: f.RuleID, ArtifactIdentity: artifact, Location: f.Location, Severity: f.Severity, Confidence: f.Confidence, Verification: state, Provenance: provenance, Classification: f.Category}, nil
}

func VerifyProjectionPreserved(before, after []SecurityProjection) error {
	key := func(p SecurityProjection) string {
		return p.EvidenceID + "\x00" + p.FindingID + "\x00" + p.RuleID + "\x00" + p.ArtifactIdentity + "\x00" + p.Location.File
	}
	want := map[string]SecurityProjection{}
	for _, p := range before {
		want[key(p)] = p
	}
	for _, p := range after {
		k := key(p)
		if prior, ok := want[k]; ok && prior.Severity == p.Severity && prior.Verification == p.Verification && prior.Classification == p.Classification {
			delete(want, k)
		}
	}
	if len(want) > 0 {
		return errors.New("security-critical evidence identity was lost or changed")
	}
	return nil
}

// ResponseProjectionProof binds raw provider output bytes to parsed payload and
// normalized findings, ensuring unmapped high-risk signals or truncated responses
// cannot silently pass as complete zero-finding results.
type ResponseProjectionProof struct {
	RawResponseDigest        string   `json:"raw_response_digest"`
	ParsedPayloadDigest      string   `json:"parsed_payload_digest"`
	NormalizedFindingDigests []string `json:"normalized_finding_digests,omitempty"`
	UnmappedCriticalSignals  []string `json:"unmapped_critical_signals,omitempty"`
	Truncated                bool     `json:"truncated"`
	SchemaValid              bool     `json:"schema_valid"`
	Complete                 bool     `json:"complete"`
}

// Validate checks that the response projection proof is complete and lossless.
func (p ResponseProjectionProof) Validate() error {
	if strings.TrimSpace(p.RawResponseDigest) == "" || strings.TrimSpace(p.ParsedPayloadDigest) == "" {
		return errors.New("response projection proof requires raw_response_digest and parsed_payload_digest")
	}
	if p.Truncated {
		return errors.New("response projection proof is truncated")
	}
	if !p.SchemaValid {
		return errors.New("response projection proof schema is invalid")
	}
	if len(p.UnmappedCriticalSignals) > 0 {
		return fmt.Errorf("response projection lost %d unmapped critical signals", len(p.UnmappedCriticalSignals))
	}
	if !p.Complete {
		return errors.New("response projection proof is not complete")
	}
	return nil
}

// BuildResponseProjectionProof constructs and validates a ResponseProjectionProof.
func BuildResponseProjectionProof(raw []byte, parsed any, findings []skil.Finding, unmappedSignals []string, truncated, schemaValid bool) (ResponseProjectionProof, error) {
	if len(raw) == 0 {
		return ResponseProjectionProof{}, errors.New("raw response bytes are empty")
	}
	rawSum := sha256.Sum256(raw)
	parsedBytes, err := json.Marshal(parsed)
	if err != nil {
		return ResponseProjectionProof{}, fmt.Errorf("marshal parsed payload: %w", err)
	}
	parsedSum := sha256.Sum256(parsedBytes)

	var findingDigests []string
	for _, f := range findings {
		fb, _ := json.Marshal(f)
		fSum := sha256.Sum256(fb)
		findingDigests = append(findingDigests, "sha256:"+hex.EncodeToString(fSum[:]))
	}
	sort.Strings(findingDigests)

	var unmapped []string
	for _, s := range unmappedSignals {
		if strings.TrimSpace(s) != "" {
			unmapped = append(unmapped, strings.TrimSpace(s))
		}
	}
	sort.Strings(unmapped)

	proof := ResponseProjectionProof{
		RawResponseDigest:        "sha256:" + hex.EncodeToString(rawSum[:]),
		ParsedPayloadDigest:      "sha256:" + hex.EncodeToString(parsedSum[:]),
		NormalizedFindingDigests: findingDigests,
		UnmappedCriticalSignals:  unmapped,
		Truncated:                truncated,
		SchemaValid:              schemaValid,
		Complete:                 !truncated && schemaValid && len(unmapped) == 0,
	}
	return proof, proof.Validate()
}

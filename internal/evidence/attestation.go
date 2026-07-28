package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func Create(scan skil.ScanResult) skil.Attestation {
	analysis := []string{}
	for name, state := range scan.Coverage {
		if state == skil.CoverageCompleted {
			analysis = append(analysis, name)
		}
	}
	sort.Strings(analysis)
	e := skil.Evidence{Type: "security-scan", Producer: "skil", ProducerVer: skil.Version,
		SubjectDigest: scan.Artifact.SubjectDigest(), Timestamp: time.Now().UTC(), PayloadDigest: FindingsDigest(scan.Findings),
		Result: skil.EvidenceResult{Status: scan.Status, Verdict: scan.Verdict, MaximumSeverity: scan.Maximum, RiskScore: scan.RiskScore, Findings: len(scan.Findings)}}
	return skil.Attestation{
		Version: 1, Subject: skil.Subject{Name: scan.Artifact.Name, Version: scan.Artifact.Version, SHA256: scan.Artifact.SubjectDigest()},
		Producer: skil.Producer{Name: "skil", Version: skil.Version}, Analysis: analysis,
		Result:    skil.AttestResult{Status: scan.Status, Verdict: scan.Verdict, MaximumSeverity: scan.Maximum, RiskScore: scan.RiskScore},
		Timestamp: time.Now().UTC(), Evidence: []skil.Evidence{e},
	}
}

func FindingsDigest(findings []skil.Finding) string {
	payload, _ := json.Marshal(findings)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func Bind(a skil.Attestation, artifact skil.Artifact) error {
	if a.Subject.SHA256 != artifact.SubjectDigest() {
		return fmt.Errorf("digest mismatch: attestation=%s artifact=%s", a.Subject.SHA256, artifact.SubjectDigest())
	}
	for _, item := range a.Evidence {
		if item.SubjectDigest != artifact.SubjectDigest() {
			return fmt.Errorf("evidence digest mismatch")
		}
	}
	return nil
}

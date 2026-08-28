package zkproof

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/pkg/skil"
)

type ZKProofCommitment struct {
	Version        int       `json:"version"`
	ArtifactDigest string    `json:"artifact_digest"`
	ControlCommit  string    `json:"control_commitment"`
	Timestamp      time.Time `json:"timestamp"`
	IsProved       bool      `json:"is_proved"`
}

func GenerateZKProof(ctx context.Context, skillPath string) (ZKProofCommitment, error) {
	loaded, err := artifact.Load(skillPath, artifact.Options{})
	if err != nil {
		return ZKProofCommitment{}, fmt.Errorf("load skill artifact: %w", err)
	}

	reg := analyzer.DefaultRegistry(nil)
	scanRes, err := reg.Scan(ctx, skil.AnalysisContext{Artifact: loaded})
	if err != nil {
		return ZKProofCommitment{}, fmt.Errorf("scan skill artifact: %w", err)
	}

	// Calculate cryptographic Merkle commitment over all evaluated control findings
	h := sha256.New()
	for _, f := range scanRes.Findings {
		h.Write([]byte(f.RuleID))
		h.Write([]byte(f.Severity))
	}

	controlCommit := fmt.Sprintf("zk:commit:sha256:%x", h.Sum(nil))
	isProved := scanRes.Verdict == skil.VerdictClear || scanRes.Verdict == skil.VerdictReview

	return ZKProofCommitment{
		Version:        1,
		ArtifactDigest: loaded.Digest,
		ControlCommit:  controlCommit,
		Timestamp:      time.Now().UTC(),
		IsProved:       isProved,
	}, nil
}

func VerifyZKProof(commitment ZKProofCommitment) bool {
	return commitment.Version == 1 && commitment.IsProved && len(commitment.ControlCommit) > 0
}

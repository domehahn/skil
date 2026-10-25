// Package continuous implements the persistent state transition for the
// explicit, one-shot continuous-assurance check.
package continuous

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/pkg/skil"
)

const SchemaVersion = "1.0.0"

type State struct {
	SchemaVersion              string    `json:"schema_version"`
	Source                     string    `json:"source"`
	ArtifactDigest             string    `json:"artifact_digest"`
	ClosureDigest              string    `json:"closure_digest,omitempty"`
	PreviousArtifactDigest     string    `json:"previous_artifact_digest,omitempty"`
	PreviousClosureDigest      string    `json:"previous_closure_digest,omitempty"`
	Changed                    bool      `json:"changed"`
	PolicyDecision             string    `json:"policy_decision"`
	RuntimePinValid            bool      `json:"runtime_pin_valid"`
	AttestationRefreshRequired bool      `json:"attestation_refresh_required"`
	CheckedAt                  time.Time `json:"checked_at"`
}

func Evaluate(previous *State, source string, scan skil.ScanResult, decision policy.Result, now time.Time) State {
	state := State{
		SchemaVersion: SchemaVersion, Source: source,
		ArtifactDigest: scan.Artifact.SubjectDigest(), PolicyDecision: decision.Decision,
		CheckedAt: now.UTC(), RuntimePinValid: false,
		AttestationRefreshRequired: true,
	}
	if scan.Closure != nil {
		state.ClosureDigest = scan.Closure.Digest
	}
	if previous == nil {
		return state
	}
	state.PreviousArtifactDigest = previous.ArtifactDigest
	state.PreviousClosureDigest = previous.ClosureDigest
	state.Changed = state.ArtifactDigest != previous.ArtifactDigest || state.ClosureDigest != previous.ClosureDigest
	state.AttestationRefreshRequired = state.Changed
	state.RuntimePinValid = !state.Changed && previous.RuntimePinValid && decision.Decision == "ALLOW"
	return state
}

func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("parse continuous state: %w", err)
	}
	if state.SchemaVersion != SchemaVersion || state.ArtifactDigest == "" {
		return State{}, errors.New("continuous state has an unsupported schema or missing artifact digest")
	}
	return state, nil
}

func Save(path string, state State) error {
	if path == "" {
		return errors.New("continuous state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".continuous-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

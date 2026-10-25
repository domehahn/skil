package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

func occurrenceOf(f skil.Finding, subjectDigest string) string {
	return skil.NewFindingOccurrenceIdentity(f.RuleID, f.Fingerprint, subjectDigest, f.Location.File,
		f.Location.StartLine, f.Location.EndLine, subjectDigest).Fingerprint
}

// EligibleForBaseline reports why a scan cannot be the basis of an
// authoritative baseline. An incomplete, budget-limited or failed scan has not
// seen every finding, so baselining it would approve unknown risk.
func EligibleForBaseline(scan skil.ScanResult) error {
	switch {
	case scan.Status == skil.StatusError:
		return errors.New("scan failed")
	case scan.Artifact.SubjectDigest() == "":
		return errors.New("scan has no subject digest")
	case scan.Completeness.Total == 0:
		return errors.New("scan has no inspection ledger; absence of findings is not proof of analysis")
	case scan.Completeness.Completeness < 1 || scan.Completeness.Failed > 0 || scan.Completeness.Skipped > 0:
		return fmt.Errorf("scan inspection is incomplete (%.1f%%)", scan.Completeness.Completeness*100)
	case len(scan.Budget.Exceeded) > 0:
		return fmt.Errorf("scan exceeded its analysis budget: %v", scan.Budget.Exceeded)
	case scan.Closure != nil && !scan.Closure.Complete:
		return errors.New("assurance closure is incomplete")
	}
	return nil
}

// CreateForScanStrict builds a sealed, occurrence-bound (version 3) baseline
// from the scan's original findings, refusing unreliable scans. Entry order is
// deterministic and independent of finding order.
func CreateForScanStrict(scan skil.ScanResult, approvedBy, reason string) (File, error) {
	if err := EligibleForBaseline(scan); err != nil {
		return File{}, fmt.Errorf("refusing to create an authoritative baseline: %w", err)
	}
	subject := scan.Artifact.SubjectDigest()
	out := CreateForScan(scan, approvedBy, reason)
	out.Version = 3
	for i := range out.Entries {
		out.Entries[i].Occurrence = occurrenceOf(scan.Findings[i], subject)
	}
	sort.SliceStable(out.Entries, func(i, j int) bool { return out.Entries[i].Occurrence < out.Entries[j].Occurrence })
	out.Integrity = out.integrity()
	return out, nil
}

func (f File) integrity() string {
	f.Integrity = ""
	for i := range f.Entries {
		f.Entries[i].ApprovedAt = f.Entries[i].ApprovedAt.UTC()
	}
	b, _ := json.Marshal(f)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Save writes the baseline atomically: a temp file in the same directory is
// fsynced and renamed over the target. A target that is a symlink or not a
// regular file is refused, so Save can never be steered to overwrite another
// file, and concurrent writers cannot interleave bytes.
func Save(path string, file File) error {
	if file.Version == 3 && file.Integrity != file.integrity() {
		return errors.New("refusing to save a baseline with an invalid integrity seal")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to overwrite non-regular file %s", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := yaml.Marshal(file)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

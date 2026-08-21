package analyzer

import (
	"context"
	"encoding/binary"
	"fmt"
	"path"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// PyC detects Python compiled bytecode (.pyc) files, decodes their PEP 552
// header, and correlates each one with an accompanying .py source file in
// the same artifact when one is present.
//
// This is deliberately narrow in what it claims. It does not decompile or
// disassemble bytecode, and it does not attempt to verify PEP 552
// hash-based pyc files against their source (that requires reproducing
// CPython's exact source-hashing scheme; getting a from-scratch
// reimplementation of that subtly wrong would be worse than not
// attempting it, since it would produce confident-looking but incorrect
// verification). What it does verify, for the far more common
// timestamp-based invalidation mode: whether the source-file byte length
// recorded in the pyc header matches the accompanying source file's
// actual size in this artifact — a coherence check that needs no
// cryptography and catches the concrete case of a .pyc shipped alongside
// a .py that isn't what it claims to have been compiled from.
type PyC struct{}

func NewPyC() *PyC { return &PyC{} }

func (p *PyC) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.pyc", Version: "1.0.0",
		Domain: "asset", Subdomain: "compiled-bytecode",
		Categories:     []string{"supply-chain-integrity"},
		AnalysisTypes:  []string{"asset"},
		SupportedTypes: []string{"pyc"},
	}
}

func (p *PyC) Rules() []skil.Rule {
	return []skil.Rule{
		{ID: "SKIL-PYC-SOURCE-MISMATCH", Title: "Compiled Python bytecode does not match its declared source",
			Category: "supply-chain-integrity", Severity: skil.SeverityHigh, Analysis: "asset",
			AppliesTo:   []string{"pyc"},
			Description: "A .pyc file's PEP 552 header records a source-file size that does not match the accompanying .py file in this artifact.",
			Remediation: "Recompile the .pyc from the exact reviewed source, or remove the stale .pyc and let Python regenerate it."},
	}
}

func (p *PyC) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if extension(file.Path) != "pyc" {
			continue
		}
		header, ok := parsePycHeader(file.Data)
		if !ok || header.Invalidation != pycTimestampBased {
			continue // unrecognized header, or hash-based: no size field to compare
		}
		source, ok := findPycSource(file.Path, ac.Artifact.Files)
		if !ok {
			continue // no accompanying source in this artifact at all
		}
		if int64(header.SourceSize) != int64(len(source.Data)) {
			evidence := fmt.Sprintf("pyc declares source size %d, %s is %d bytes", header.SourceSize, source.Path, len(source.Data))
			out = append(out, makeFinding(RulePattern{Rule: p.Rules()[0], Confidence: .9}, file, 1, evidence))
		}
	}
	return out, nil
}

type pycInvalidationMode int

const (
	pycTimestampBased pycInvalidationMode = iota
	pycHashChecked
	pycHashUnchecked
)

type pycHeader struct {
	// PythonVersion is a best-effort label from a table of published
	// CPython bytecode magic numbers; "unknown (magic 0x____)" for any
	// magic number not in the table, rather than guessing.
	PythonVersion string
	Invalidation  pycInvalidationMode
	// SourceMTime/SourceSize are only meaningful when Invalidation ==
	// pycTimestampBased; for a hash-based pyc these header bytes instead
	// hold an 8-byte source hash this package does not attempt to verify.
	SourceMTime uint32
	SourceSize  uint32
}

// parsePycHeader decodes the 16-byte PEP 552 header used by Python 3.7+.
// Older pre-3.7 8-byte headers (magic+mtime, no flags or size field) are
// deliberately not recognized here — ok is false for anything that isn't
// unambiguously a modern-format pyc, rather than guessing at a shorter,
// less specific header.
func parsePycHeader(data []byte) (pycHeader, bool) {
	if len(data) < 16 {
		return pycHeader{}, false
	}
	if data[2] != 0x0D || data[3] != 0x0A {
		return pycHeader{}, false
	}
	magic := binary.LittleEndian.Uint16(data[0:2])
	flags := binary.LittleEndian.Uint32(data[4:8])
	header := pycHeader{PythonVersion: pycMagicNumbers[magic]}
	if header.PythonVersion == "" {
		header.PythonVersion = fmt.Sprintf("unknown (magic 0x%04x)", magic)
	}
	switch {
	case flags&0b01 == 0:
		header.Invalidation = pycTimestampBased
		header.SourceMTime = binary.LittleEndian.Uint32(data[8:12])
		header.SourceSize = binary.LittleEndian.Uint32(data[12:16])
	case flags&0b10 != 0:
		header.Invalidation = pycHashChecked
	default:
		header.Invalidation = pycHashUnchecked
	}
	return header, true
}

// pycMagicNumbers is a best-effort, incomplete table of published CPython
// bytecode magic numbers (Lib/importlib/_bootstrap_external.py's
// MAGIC_NUMBER history) for recent, still-common interpreter versions. A
// magic number not in this table reports as "unknown" rather than a wrong
// guess — CPython bumps this value on bytecode format changes, not
// strictly once per release, so within-version accuracy across every
// patch release is not guaranteed.
var pycMagicNumbers = map[uint16]string{
	3394: "3.7", 3413: "3.8", 3425: "3.9", 3439: "3.10", 3495: "3.11", 3531: "3.12", 3571: "3.13",
}

// findPycSource locates the .py file in the artifact that a given .pyc
// path would have been compiled from, following both conventions Python
// actually uses:
//   - __pycache__/module.cpython-311.pyc -> module.py in the parent
//     directory of __pycache__
//   - module.pyc (no __pycache__, e.g. Python 2 or an explicit compile
//     step) -> module.py in the same directory
func findPycSource(pycPath string, files []skil.File) (skil.File, bool) {
	dir, base := path.Split(pycPath)
	dir = strings.TrimSuffix(dir, "/")
	name := strings.TrimSuffix(base, ".pyc")
	var candidateDir, moduleName string
	if lastDir := path.Base(dir); lastDir == "__pycache__" {
		candidateDir = strings.TrimSuffix(dir, "__pycache__")
		candidateDir = strings.TrimSuffix(candidateDir, "/")
		// Strip the "cpython-311"-style version tag Python appends
		// before the final extension.
		if idx := strings.LastIndex(name, "."); idx >= 0 {
			moduleName = name[:idx]
		} else {
			moduleName = name
		}
	} else {
		candidateDir = dir
		moduleName = name
	}
	sourcePath := moduleName + ".py"
	if candidateDir != "" {
		sourcePath = candidateDir + "/" + sourcePath
	}
	for _, file := range files {
		if file.Path == sourcePath {
			return file, true
		}
	}
	return skil.File{}, false
}

package artifact

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

// Nested Artifact Virtualization: a ZIP-compatible container (.zip, or an
// Open XML document — .docx/.xlsx/.pptx — which is just a ZIP with a
// specific internal structure) found as a regular file inside the artifact
// is itself expanded, bounded, and fed into the same analyzer pipeline as
// every other file, with a provenance path recording exactly where it came
// from (outer.docx!/embedded.zip!/scripts/setup.sh) — so an analyzer never
// has to know or care that a file arrived via container expansion rather
// than directly from the artifact's own file list.
//
// This only recognizes ZIP-family containers; it does not recurse into
// .tar/.tar.gz/.tgz members found as regular files (the top-level artifact
// package format already supports .tgz — see loadTGZ — but a .tar.gz
// discovered as an ordinary file inside an artifact is not virtualized in
// this first pass).
//
// All bounds below are a single shared budget across every container
// virtualized for one artifact, not a per-container budget: a skill
// shipping many small containers cannot bypass the aggregate limit by
// splitting content across them, matching the same reasoning
// MaxTotalSize/MaxFiles already apply to the top-level archive loader.
const (
	// MaxContainerDepth bounds how many levels of nested container a
	// single chain may reach (a .zip inside a .zip inside a .docx, ...).
	MaxContainerDepth = 3
	// MaxContainerMembers bounds the total number of files materialized
	// from nested containers across the whole artifact.
	MaxContainerMembers = 1_000
	// MaxContainerExpandedBytes bounds the total decompressed bytes
	// materialized from nested containers across the whole artifact.
	MaxContainerExpandedBytes = 25 << 20
	// MaxContainerMemberBytes bounds a single materialized member.
	MaxContainerMemberBytes = 1 << 20
	// MaxContainerCompressionRatio bounds uncompressed:compressed size
	// for any one member — a classic zip-bomb defense.
	MaxContainerCompressionRatio = 100
	// MaxContainerInspectTime bounds total wall-clock time spent
	// virtualizing nested containers for one artifact.
	MaxContainerInspectTime = 5 * time.Second
)

type containerBudget struct {
	membersRemaining       int
	expandedBytesRemaining int64
	deadline               time.Time
}

func (b *containerBudget) exhausted() bool {
	return b.membersRemaining <= 0 || b.expandedBytesRemaining <= 0 || time.Now().After(b.deadline)
}

// VirtualizeNestedContainers scans every file already loaded for the
// artifact and, for each one that looks like a ZIP-compatible container,
// recursively materializes its members (and their own nested containers,
// up to MaxContainerDepth) as additional skil.File entries. It never
// mutates or removes the original files — the container itself is still
// scanned as an ordinary (opaque, for analyzability purposes) binary file
// exactly as it always was; virtualization is purely additive.
func VirtualizeNestedContainers(files []skil.File) ([]skil.File, []skil.Diagnostic) {
	budget := &containerBudget{
		membersRemaining: MaxContainerMembers, expandedBytesRemaining: MaxContainerExpandedBytes,
		deadline: time.Now().Add(MaxContainerInspectTime),
	}
	var virtual []skil.File
	var diagnostics []skil.Diagnostic
	// Only top-level files are candidate roots here; recursion within one
	// container's own nested containers happens inside virtualizeContainer
	// itself, so a virtual file produced by this pass is never re-scanned
	// as a new root by this loop (which would reprocess it a second time).
	for _, file := range files {
		if !looksLikeZip(file.Data) {
			continue
		}
		if budget.exhausted() {
			diagnostics = append(diagnostics, containerDiagnostic(file.Path, "nested-container budget already exhausted before this container was reached"))
			continue
		}
		nested, diags := virtualizeContainer(file, budget)
		virtual = append(virtual, nested...)
		diagnostics = append(diagnostics, diags...)
	}
	return virtual, diagnostics
}

func looksLikeZip(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04
}

func containerDiagnostic(path, reason string) skil.Diagnostic {
	return skil.Diagnostic{Component: "nested-container", Level: "warning", Message: fmt.Sprintf("%s: %s", path, reason)}
}

func virtualizeContainer(container skil.File, budget *containerBudget) ([]skil.File, []skil.Diagnostic) {
	depth := container.ContainerDepth + 1
	if depth > MaxContainerDepth {
		return nil, []skil.Diagnostic{containerDiagnostic(container.Path, fmt.Sprintf("nested-container depth limit (%d) exceeded", MaxContainerDepth))}
	}
	reader, err := zip.NewReader(bytes.NewReader(container.Data), int64(len(container.Data)))
	if err != nil {
		// Not actually a valid ZIP despite the magic bytes matching (a
		// coincidental prefix, or a deliberately malformed file) — this is
		// not a load failure, just nothing further to virtualize here.
		return nil, nil
	}
	if len(reader.File) > budget.membersRemaining {
		return nil, []skil.Diagnostic{containerDiagnostic(container.Path, fmt.Sprintf("nested-container member count (%d) exceeds remaining budget (%d); container skipped entirely", len(reader.File), budget.membersRemaining))}
	}
	// containerRawSHA256 is the parent digest every member materialized
	// from this container records: for a depth-0 container, that is
	// simply its own File.SHA256 (the raw-byte digest computed at load
	// time, before any text canonicalization).
	containerRawSHA256 := container.SHA256

	var out []skil.File
	var diagnostics []skil.Diagnostic
	seen := map[string]bool{}
	for _, entry := range reader.File {
		if budget.exhausted() {
			diagnostics = append(diagnostics, containerDiagnostic(container.Path, "nested-container budget exhausted; remaining members in this container were not materialized"))
			break
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			diagnostics = append(diagnostics, containerDiagnostic(container.Path, "symlinked member rejected: "+entry.Name))
			continue
		}
		name, err := safeArchivePath(entry.Name)
		if err != nil {
			diagnostics = append(diagnostics, containerDiagnostic(container.Path, err.Error()))
			continue
		}
		provenancePath := container.Path + "!/" + name
		if seen[strings.ToLower(provenancePath)] {
			diagnostics = append(diagnostics, containerDiagnostic(container.Path, "duplicate or case-colliding member rejected: "+name))
			continue
		}
		seen[strings.ToLower(provenancePath)] = true
		if entry.UncompressedSize64 > MaxContainerMemberBytes {
			diagnostics = append(diagnostics, containerDiagnostic(provenancePath, "member exceeds per-file materialization limit; not materialized"))
			continue
		}
		if entry.CompressedSize64 > 0 && entry.UncompressedSize64/entry.CompressedSize64 > MaxContainerCompressionRatio {
			diagnostics = append(diagnostics, containerDiagnostic(provenancePath, "member exceeds maximum compression ratio; not materialized (zip-bomb defense)"))
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			diagnostics = append(diagnostics, containerDiagnostic(provenancePath, "failed to open member: "+err.Error()))
			continue
		}
		limited := boundedRead(rc, MaxContainerMemberBytes)
		rc.Close()
		if limited == nil {
			diagnostics = append(diagnostics, containerDiagnostic(provenancePath, "member read exceeded per-file materialization limit; not materialized"))
			continue
		}
		if int64(len(limited)) > budget.expandedBytesRemaining {
			diagnostics = append(diagnostics, containerDiagnostic(provenancePath, "materializing this member would exceed the remaining nested-container byte budget; not materialized"))
			budget.expandedBytesRemaining = 0
			continue
		}
		budget.expandedBytesRemaining -= int64(len(limited))
		budget.membersRemaining--

		sum := sha256.Sum256(limited)
		canonical, encoding := canonicalizeText(limited)
		virtualFile := skil.File{
			Path: provenancePath, Data: canonical, SHA256: hex.EncodeToString(sum[:]),
			Executable: entry.Mode()&0o111 != 0, Encoding: encoding,
			ContainerDepth: depth, ContainerParentSHA256: containerRawSHA256,
		}
		out = append(out, virtualFile)

		if looksLikeZip(limited) && depth < MaxContainerDepth && !budget.exhausted() {
			deeper, deeperDiags := virtualizeContainer(virtualFile, budget)
			out = append(out, deeper...)
			diagnostics = append(diagnostics, deeperDiags...)
		}
	}
	return out, diagnostics
}

// boundedRead reads at most limit bytes; if more remain (the entry lied
// about, or the reader produces more than, its declared uncompressed
// size), it returns nil rather than a truncated buffer, so a caller never
// mistakes a truncated read for the member's genuine complete content.
func boundedRead(rc interface{ Read([]byte) (int, error) }, limit int64) []byte {
	buf := make([]byte, 0, limit)
	chunk := make([]byte, 32*1024)
	var total int64
	for {
		n, err := rc.Read(chunk)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return nil
			}
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf
}

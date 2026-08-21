package analyzer

import "github.com/domehahn/skil/pkg/skil"

// classifyAnalyzability answers a narrower question than the inspection
// ledger does: not "did every applicable analyzer run to completion" but
// "was this file's actual content genuinely visible to analysis". A file
// can score 100% on the former while being completely opaque on the
// latter — e.g. a Windows PE executable has no applicable "text" analyzer
// to skip in the first place, so nothing in the inspection ledger flags
// it as a gap, yet skil cannot read a single instruction of what it does.
//
// v1 draws the line at two signals. The primary one: whether
// canonicalizeText (see internal/artifact) recognized the file as text.
// That alone does not yet distinguish "text that failed to parse as an
// AST" (partial) from "text fully understood" (full) — nothing emits
// that distinction yet. The second, narrower signal: a recognized .pyc
// file (see pyc.go) with an accompanying .py source present in this
// artifact is partial rather than opaque — the bytecode itself is still
// unread, but its declared source is available for every other analyzer
// to inspect, which a compiled binary with no source never offers.
func classifyAnalyzability(file skil.File, allFiles []skil.File) skil.AnalyzabilityRecord {
	record := skil.AnalyzabilityRecord{
		Path: file.Path, Encoding: file.Encoding, Executable: file.Executable, SHA256: file.SHA256,
	}
	if isText(file) {
		record.State = skil.AnalyzabilityFull
		return record
	}
	if extension(file.Path) == "pyc" {
		if header, ok := parsePycHeader(file.Data); ok {
			if source, hasSource := findPycSource(file.Path, allFiles); hasSource {
				record.State = skil.AnalyzabilityPartial
				record.BinaryKind = "Python compiled bytecode (.pyc, " + header.PythonVersion + ")"
				record.Reason = "accompanying source " + source.Path + " is present in this artifact; the compiled bytecode itself is not decompiled or read"
				return record
			}
			record.State = skil.AnalyzabilityOpaque
			record.BinaryKind = "Python compiled bytecode (.pyc, " + header.PythonVersion + ")"
			record.Reason = "no accompanying .py source in this artifact; skil does not decompile bytecode"
			return record
		}
	}
	record.State = skil.AnalyzabilityOpaque
	record.BinaryKind = disguisedBinaryKind(file.Data)
	switch {
	case record.BinaryKind != "":
		record.Reason = record.BinaryKind + "; content is executable/archive binary skil does not decompile or unpack for semantic analysis"
	case file.Executable:
		record.Reason = "executable bit set on non-text content of an unrecognized binary format"
	default:
		record.Reason = "binary content of an unrecognized or non-executable format"
	}
	return record
}

func summarizeAnalyzability(records []skil.AnalyzabilityRecord) skil.AnalyzabilitySummary {
	summary := skil.AnalyzabilitySummary{Files: len(records)}
	for _, record := range records {
		switch record.State {
		case skil.AnalyzabilityFull:
			summary.Full++
		case skil.AnalyzabilityPartial:
			summary.Partial++
		case skil.AnalyzabilityOpaque:
			summary.Opaque++
		}
	}
	if summary.Files == 0 {
		summary.Coverage = 1
	} else {
		summary.Coverage = (float64(summary.Full) + 0.5*float64(summary.Partial)) / float64(summary.Files)
	}
	return summary
}

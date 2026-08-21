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
// v1 draws the line at exactly one signal: whether canonicalizeText (see
// internal/artifact) recognized the file as text. That is deliberately
// the only thing this function claims — it does not yet attempt to
// distinguish "text that failed to parse as an AST" (partial) from "text
// fully understood" (full), and it does not yet correlate compiled
// bytecode with an available source file. AnalyzabilityPartial exists in
// the schema for exactly those future refinements; nothing emits it yet.
func classifyAnalyzability(file skil.File) skil.AnalyzabilityRecord {
	record := skil.AnalyzabilityRecord{
		Path: file.Path, Encoding: file.Encoding, Executable: file.Executable, SHA256: file.SHA256,
	}
	if isText(file) {
		record.State = skil.AnalyzabilityFull
		return record
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

# Change 0012: Derived security views

## Context

SKIL's `builtin.obfuscation` analyzer detects invisible Unicode, bidi controls,
mixed-script tokens, Unicode tag smuggling, and selected Base64 instructions.
Those transformations are analyzer-local and do not let the rest of the
deterministic analyzer registry inspect reconstructed content. They also lack a
shared transformation budget and byte-offset provenance back to the immutable
root artifact.

This change is Epic 1 of the ordered assurance roadmap. The evidence graph,
workspace/session closure, dynamic verification, delegation, and continuous
competitive assurance epics depend on this representation layer and remain
separate follow-on changes.

## Requirements and acceptance criteria

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| DSV-01 | Deterministic reconstruction | Identical input and budget produce byte-identical ordered view metadata and digests. |
| DSV-02 | Required transformations | Default-ignorables, bidi, curated confusables, inter-character spacing, explicit marker removal, Base64, hex, URL encoding, escaped strings, and simple literal concatenation have positive and negative tests. |
| DSV-03 | Provenance | Every derived finding names its view, transformation chain, original byte range, and original source path. |
| DSV-04 | Analyzer reuse | Existing deterministic analyzers inspect derived views through the registry without duplicating their rules. |
| DSV-05 | Monotonic evidence | Original findings remain present; derived evidence is additive and cannot suppress or downgrade it. |
| DSV-06 | Fail closed | Ambiguous explicit encodings, transformation failures, and exhausted view/depth/byte budgets degrade coverage and prevent a trusted result. |
| DSV-07 | Resource safety | View count, composition depth, decoded bytes, and output growth are bounded before more analyzer work starts. |
| DSV-08 | Robustness | Malformed hostile input is fuzzed without panic, unbounded allocation, or nondeterministic output. |
| DSV-09 | Compatibility | Existing analyzer interfaces and JSON consumers remain valid; new model and budget fields are additive. |

## Design decision

Add a pure `internal/derived` package between immutable artifact ingestion and
the analyzer registry. It builds full-file alternative views in a fixed
transformation order, maintains an output-byte to original-byte span map, and
deduplicates by content digest. Composition uses breadth-first traversal with
explicit per-scan limits.

The registry continues to analyze the original artifact first. It then invokes
the same deterministic analyzers on eligible derived files and keeps only
results whose derived location intersects transformed output. Findings and
observations are annotated with transformation and original-offset evidence.
The semantic-provider pass is excluded from reconstruction itself; no model is
used to decode content.

Marker removal is intentionally narrow. Only a preceding explicit declaration
using `obfuscation-marker`, `remove-marker`, or `separator-character` and one
quoted/single punctuation character activates removal. Arbitrary punctuation is
never guessed to be concealment.

## Threat model

- **Tampering/evasion:** chained encodings hide a deterministic dangerous fact.
  Control: bounded composition and additive analyzer reuse.
- **Repudiation:** a derived alert cannot be traced to supplied bytes. Control:
  original byte spans, source digest, transformation chain, and view digest.
- **Denial of service:** recursive decoding expands exponentially. Control:
  strict depth, view-count, output-byte, token-size, and growth-ratio limits.
- **Information disclosure:** preprocessing sends content to a provider.
  Control: derivation is local and deterministic; no network or model calls.
- **Spoofing/confusion:** a guessed marker changes benign meaning. Control:
  explicit declaration grammar and preservation of the original view.

Residual risk: reconstruction is intentionally incomplete for encrypted,
compressed-without-format, computed, or runtime-only obfuscation. Unsupported
or ambiguous explicit encodings produce `UNKNOWN`, not a safety claim.

## Rollback

Remove `internal/derived`, registry integration, additive model/budget fields,
fixtures, and documentation. Original analyzer behavior remains intact because
the pipeline always runs it independently before derived views.

## Validation

```text
go test ./internal/derived ./internal/analyzer
go test ./...
go test -race ./...
go vet ./...
make lint
```

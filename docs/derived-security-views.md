# Derived security views

Derived security views are bounded, deterministic alternative representations
of immutable artifact bytes. They let existing analyzers inspect reconstructed
content without teaching each rule how to decode every concealment technique.
The original artifact is always analyzed independently and remains the source
of truth.

## Supported transformations

The preprocessing layer applies a fixed transformation order and may compose
views up to the configured depth:

- Unicode default-ignorable removal, while retaining legitimate emoji ZWJ use;
- bidi-control removal;
- Unicode variation-selector (supplement, U+E0100-U+E01EF) removal;
- curated Cyrillic/Greek confusable normalization;
- mathematical alphanumeric symbol normalization (U+1D400-U+1D7FF), verified
  against the Unicode character database, Latin letters and digits only;
- fullwidth form normalization (U+FF01-U+FF5E plus the ideographic space
  U+3000);
- collapse of runs of single characters separated by spaces or tabs;
- removal of a punctuation marker only after an explicit
  `obfuscation-marker`, `remove-marker`, or `separator-character` declaration;
- printable Base64 and hexadecimal decoding;
- URL percent decoding;
- quoted escape-sequence decoding;
- joining simple quoted string-literal concatenations;
- Braille-pattern (U+2800-U+28FF) byte decoding, for runs of four or more
  cells, kept only when the decoded bytes are printable — genuine Braille
  transliteration of language text uses an unrelated encoding and does not
  generally survive this check;
- shell/script line-continuation joining: a trailing backslash immediately
  before a line ending is removed the same way POSIX shell and Python treat
  it, so a command fragmented across several lines reconstructs to the single
  logical line an existing rule already matches, at that rule's own
  unmodified severity.

This is not general evaluation or model-based deobfuscation. SKIL does not
execute reconstructed content and does not make a network request to derive a
view.

## Provenance and evidence

Every view records its source path and digest, derived content digest, depth,
and ordered transformation steps. Each step maps its input/output byte range to
an original artifact byte span. A finding emitted from a derived view retains
the original path and line while adding:

```text
derived_view_id
derived_view_digest
derived_source_digest
derived_transformations
original_start_offset
original_end_offset
```

Only findings whose derived line intersects transformed output are retained;
unchanged duplicate results from the alternative view are discarded. Original
findings are never replaced or suppressed.

## Budgets and incomplete analysis

`AnalysisBudget` includes `MaxDerivedViews`, `MaxDerivedDepth`, and
`MaxDerivedBytes`. Defaults are 64 views, depth 3, and 16 MiB of cumulative
derived bytes per scan. They are global scan limits, not per-transform limits.
Individual encoded tokens and view growth also have hard internal bounds.

Exhausting a bound, cancelling reconstruction, failing derived analysis, or
encountering a malformed explicit `base64:`, `hex:`, or `url-encoded:` value
sets `derived-views` coverage to `degraded`. That prevents `CLEAR` and makes the
assurance closure `UNKNOWN` unless stronger unsafe evidence already exists.

Machine-readable output exposes `derived_security_views` metadata and the
three derived budget dimensions. Terminal, Markdown, and HTML reports show a
compact summary rather than dumping reconstructed content.

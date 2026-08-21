# Security scanning

The complete positive/negative control inventory is documented in
[`security-control-matrix.md`](security-control-matrix.md).

Normal scans use a small, versioned built-in offline reputation set with
provenance metadata; it initially recognizes the abandoned PyPI `pycrypto`
package. Use `--dependency-reputation evidence.json` to add reviewed, offline
package metadata. The strict version-1 evidence format is defined by
`schemas/dependency-reputation-v1.schema.json`; malformed or duplicate records
fail closed.

Container trust disabling is detected independently from generic transport
checks. Unicode analysis covers invisible/Bidi controls and mixed
Latin/Cyrillic hostname confusables.

Built-in analysis covers instruction and activation integrity, data-boundary
violations, trusted-context disclosure, state manipulation, dangerous
Python/Shell/JS/TS operations, dependency hygiene, MCP permissions, metadata
injection and mutable identity, Unicode deception, infrastructure boundaries,
and bounded data-flow analysis.

Python analysis uses the official Tree-sitter Python grammar to build a complete
syntax tree. It resolves direct imports, aliases, from-imports, call nodes,
subscript environment access, keyword arguments, and dynamic attribute access
without importing or executing the module. A deterministic whole-artifact
function-summary pass connects direct source and sink wrappers across files.
Dynamic dispatch, reflection, implicit flows, and runtime-generated code remain
outside static proof and are handled by the assurance runtime.

JavaScript, TypeScript/TSX, and Bash also use official Tree-sitter grammars.
Security matching is restricted to syntax nodes such as calls, member access,
commands, and pipelines so comments and unrelated string literals do not become
code findings. These analyzers do not perform whole-program type resolution or
dynamic module resolution.

Taint tracking is deterministic, syntax-aware, and deliberately bounded. It
propagates multi-step assignment aliases, recognizes explicit sanitizer calls,
and builds cross-file function summaries for direct source/sink wrappers.
Sink summaries retain the exact consumed parameter positions, preventing an
unrelated tainted argument from being attributed to a safe wrapper parameter.
Evidence identifies whether a finding came from direct syntax flow or the
whole-artifact summary engine.

`--osv` performs explicit, fail-closed vulnerability lookup for pinned
dependencies through bounded batches. `--osv-cache FILE` enables an
integrity-checked cache; `--osv-offline` requires it. Expired entries are used
only in explicit offline mode or as a visible degraded fallback after an online
failure.

`--full` is explicit consent to online OSV lookup and also enables the
independent built-in malware pack. The pack runs in native Go and therefore
does not depend on a host `yara` executable. Deterministic local semantic
analysis always runs offline. `--full` never transmits an artifact: extended
model-backed semantic analysis still requires `--semantic` and an explicit
model configuration.

`--yara-rules` invokes an installed YARA binary with trusted source rules.
`--yara-rules-dir` accepts only a bounded flat directory of regular,
non-symlink `.yar`/`.yara` files and deterministically materializes them into
one narrow temporary source. `--yara-builtin` uses skil's reviewable embedded
conditions through the native bounded evaluator. External rules retain time,
rule-count, byte, output, and temporary-file limits. None is reported completed
unless it actually ran.

The `semantic` coverage entry represents deterministic local cross-file
intent/implementation analysis. `semantic-provider` separately reports whether
an explicitly configured model-backed review ran.

`skil assure` closes the operational gap between static evidence and runtime
claims. It requires a valid contract, an isolated non-shell agent adapter, and
an eval specification that mandates containment, enforcement, and native
isolation. The combined result passes only when scan, verification, behavioral
evaluation, containment, and the host-mediated capability gateway all pass for
the same artifact digest.

`skil mcp assure <skill> --runtime-command executable` closes a gap static
analysis structurally cannot: `SKIL-MCP-005` can only compare an MCP
manifest *file* against `.skil/mcp-tools.lock.json`, but a server can present
one description in that manifest and a different one over the wire. Dynamic
assurance launches the operator-supplied MCP server command inside the same
sandboxed isolation `skil assure` uses (never an artifact-declared command
run automatically), performs the real `initialize` /
`notifications/initialized` / `tools/list` / `prompts/list` / `resources/list`
JSON-RPC-over-stdio handshake, and flags any tool (`SKIL-MCP-011`) whose
live description hashes to something other than its locked digest, or that
was never declared in the lock at all — a rug pull confirmed by execution,
not just by parsing. Every round trip is timeout-bounded and every response
frame size-bounded, so a hung or oversized-response server fails closed
rather than stalling or exhausting the caller.

Deterministic Threat-Chain Correlation runs once per scan, after every
analyzer has produced its findings and capability observations, and checks
a fixed, reviewable catalog of named attack patterns — each one a specific
combination of existing rule IDs that must *all* independently fire in the
same skill. A hidden/encoded instruction is one finding and a confirmed
taint flow to an execution sink is another; together they are
`SKIL-CHAIN-INJECT-EXEC`, because the injected instruction now has a
concrete place to run rather than a merely theoretical one. This is
deliberately not a general graph/taint engine or a semantic/ML score: a
chain firing is exactly as explainable and reproducible as any single rule,
and its evidence lists exactly which constituent findings satisfied it.
`skil compose` remains the cross-skill counterpart; threat chains correlate
within one skill's own already-computed results.

Dependency inventory covers `requirements.txt`, `pyproject.toml`,
`poetry.lock`, `uv.lock`, `package.json`, `package-lock.json`, `go.mod`,
`Cargo.toml`, `Cargo.lock`, `Gemfile.lock`, and Maven `pom.xml`. Parsing is
deterministic and offline; it does not claim full package-manager resolution.
`pyproject.toml` is parsed as TOML and project dependencies are parsed into
PEP 508 name, extras, version specifier, direct URL, and environment-marker
fields. Project metadata strings are not treated as dependencies.

The default terminal report is a detailed review view with components,
severity-ordered findings, evidence, remediation, analyzer status, exact
coverage states, and diagnostics. `--compact` selects the terse legacy terminal
view. JSON and SARIF schemas are unchanged.

ZIP and TGZ packages with one unambiguous top-level directory containing
`SKILL.md` are normalized to the same artifact-relative paths as directory
input. This includes exact discovery of `.skil/mcp-tools.lock.json`; nested
suffix matches are never used.

The same `--osv`, `--yara-rules`, and `--semantic` configuration is accepted by
`scan`, `verify`, `attest`, `policy check`, `install`, and `update`. This keeps
previewed coverage and release-gate coverage reproducible.

Each scan contains an inspection ledger for every registered analyzer/file
decision. `out_of_scope` is distinct from completed work, and the summary
reports an exact completeness ratio. `--require-complete` turns incomplete
applicable work into a blocking verdict. Policies can enforce the same property
with `minimum_inspection_completeness: 1`; signed native attestations bind both
the summary and the exact ledger digest.

Inspection completeness answers "did every applicable analyzer run" — a
different question from whether a file's actual content was visible to
analysis at all. A binary format has no applicable text analyzer to skip in
the first place, so it can't lower completeness, yet skil cannot read a
single instruction of what it does. Each scan also contains an
analyzability ledger (`AnalyzabilityRecord` per file, `state` one of
`full`/`partial`/`opaque`) and summary (`analyzability_summary`, with a
blended `coverage` ratio) that captures exactly that. A recognized
executable or archive format (PE, ELF, Mach-O, ZIP) gets its `binary_kind`
recorded; any other binary content is opaque without one. Policies can
enforce a minimum with `minimum_analyzability: <ratio>`, and specifically
deny shipping executable content skil couldn't inspect with
`deny_opaque_executable_content: true` — the latter only fires on content
recognized as executable/archive or carrying the executable bit, not on
ordinary opaque binary data like images or fonts.

Nested Artifact Virtualization: a ZIP-compatible container (`.zip`, or an
Open XML document — `.docx`/`.xlsx`/`.pptx`, which is just a ZIP with a
specific internal structure) found as a regular file inside the artifact is
itself bounded-expanded, at artifact load time, and its members are added as
additional files with a provenance path recording exactly where they came
from (`report.docx!/embedded.zip!/evil.py`) — so a payload hidden inside a
container-inside-a-container reaches the same AST, taint, dependency, MCP,
secret, and semantic analysis any ordinary file does, rather than only ever
being visible as one opaque binary blob. Each materialized file records its
nesting depth (`container_depth`) and its immediate parent's raw-byte digest
(`container_parent_sha256`); the container itself is still scanned and
reported as an ordinary (opaque) binary file exactly as it always was —
virtualization is purely additive, never a replacement. Bounds are a single
shared budget across every container virtualized for one artifact, not
per-container: nesting depth (3), total materialized members (1,000), total
materialized bytes (25 MiB), a single member (1 MiB), compression ratio
(100:1, a zip-bomb defense), and wall-clock time (5s). Any bound reached
produces a `nested-container` diagnostic (visible in the terminal report's
LIMITATIONS & DIAGNOSTICS section and JSON `diagnostics`) rather than either
silently skipping the content or failing the whole scan. Only ZIP-family
containers are virtualized in this first pass; a `.tar.gz` found as an
ordinary file inside an artifact is not (the top-level artifact *package*
format already supports `.tgz` independently of this).

Every scan draws from a single shared `AnalysisBudget` (raw bytes, expanded
bytes from nested containers, findings, inspection events, wall time) — a
resource backstop against a pathological or adversarial artifact, not a
routine constraint (the defaults are generous enough no realistic skill
scan hits them). Only the wall-time dimension is actually enforced mid-scan
(via a context deadline: an analyzer whose own deadline expires is skipped
rather than left to run unbounded, with the analysis budget's own deadline
distinguished from any deadline the caller's own context carried); the
other dimensions are measured against the completed scan and reported,
since silently truncating findings or file content mid-analysis would
itself be a correctness risk. Any dimension exceeded raises the scan's
`Status` to at least `WARN`, adds an `analysis-budget` diagnostic, and is
recorded per-dimension (used/limit) in `analysis_budget`. `--fail-on-incomplete`
turns an exceeded budget into a hard gate failure; a reviewed policy can
enforce the same with `deny_budget_exhausted: true`.

Charset smuggling: content encoded as UTF-16 (with or without a byte-order
mark) or UTF-8-with-BOM is detected and transcoded to canonical UTF-8 once,
at artifact load time, before any analyzer runs — every "text"-scoped
analyzer sees the artifact's actual content regardless of source encoding.
The detected encoding is recorded per file (`encoding` field) and, when a
file was transcoded, called out in the terminal report's "ENCODING NOTES"
section. `File.SHA256` is always the digest of the original, untranscoded
bytes, so content-addressing and attestation digests are unaffected.
Binary content round-trips completely unchanged.

Compiled Python bytecode (`.pyc`): the PEP 552 header is decoded (magic
number → a best-effort Python version label, falling back to "unknown
(magic 0x____)" rather than a wrong guess; invalidation mode: timestamp-
based, checked-hash, or unchecked-hash). A `.pyc` with no accompanying
`.py` source in the same artifact is `opaque` in the analyzability
ledger — skil does not decompile bytecode. One with a source present is
`partial`: for the common timestamp-based invalidation mode, the
header's recorded source-file size is compared against the accompanying
source's actual byte length in this artifact, and a mismatch raises
`SKIL-PYC-SOURCE-MISMATCH` (HIGH) — the concrete case of a `.pyc` that
wasn't compiled from the source it ships next to, which a reviewer
reading only the `.py` file would miss. Hash-based `.pyc` files are not
cryptographically verified against their source (reimplementing
CPython's exact source-hashing scheme incorrectly would be worse than
not attempting it) — only the timestamp-based size check is performed.

`scan-all` discovers concrete `SKILL.md` roots below a local or explicitly
allowed remote collection and returns one independently digest-bound result per
skill. `--workers` provides bounded parallelism while preserving discovery
order in JSON and Markdown output. A shared OSV cache requires `--workers 1` to
avoid cross-scan cache replacement.

`compose <collection>` scans the same discovered skills individually, then
correlates their `CapabilityObservation`s across skills for combinations
that are only a risk in composition: a skill with credential/secret-read
access that writes a resource (a file path, by concrete value), and a
*different* skill with network-outbound access that reads that same
resource. Neither skill's own `scan` result names this — each only
observes its own capabilities — so this is a genuinely new signal, not a
restatement of `SKIL-SEC-001`/`SKIL-NET-001`-style single-skill findings.
It emits `SKIL-COMPOSE-TOXIC-FLOW` (CRITICAL) per linked pair. This does
not build a general cross-skill taint/data-flow graph — it correlates
existing per-skill capability observations by shared concrete resource
value, which needs no new analysis machinery. Requires at least two
skills in the collection.

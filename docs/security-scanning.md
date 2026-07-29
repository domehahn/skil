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

`scan-all` discovers concrete `SKILL.md` roots below a local or explicitly
allowed remote collection and returns one independently digest-bound result per
skill. `--workers` provides bounded parallelism while preserving discovery
order in JSON and Markdown output. A shared OSV cache requires `--workers 1` to
avoid cross-scan cache replacement.

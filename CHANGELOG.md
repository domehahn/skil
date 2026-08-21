# Changelog

## Unreleased

- Added a `.pyc` compiled-Python-bytecode analyzer: decodes the PEP 552
  header (Python version, invalidation mode), correlates each `.pyc` with
  an accompanying `.py` source in the same artifact when present, and
  flags `SKIL-PYC-SOURCE-MISMATCH` when a timestamp-based header's
  recorded source size doesn't match that source's actual byte length —
  the case of a `.pyc` shipped next to a `.py` it wasn't compiled from. A
  `.pyc` with no accompanying source is `opaque` in the analyzability
  ledger; one with source present is `partial`.

- Added an analyzability model, distinct from inspection completeness:
  each scan now reports, per file, whether its content was actually
  visible to analysis (`full`/`partial`/`opaque`) rather than just
  whether every applicable analyzer ran. A recognized executable/archive
  format gets its kind recorded (`binary_kind`); policies can enforce
  `minimum_analyzability` and `deny_opaque_executable_content`.

- Added charset-smuggling defense: content encoded as UTF-16 (with or
  without a byte-order mark) or UTF-8-with-BOM is now detected and
  transcoded to canonical UTF-8 once, at artifact load time, before any
  analyzer runs. Previously, every "text"-scoped analyzer determined
  applicability via a check that rejected any content with embedded NUL
  bytes — which UTF-16 text is full of — so a prompt-injection payload
  saved as UTF-16 reached zero rules and scanned clean at 100% inspection
  completeness (a genuinely misleading result, not just a silent skip:
  the file was marked as inspected, not out-of-scope). The detected
  encoding is recorded on each file (`skil.File.Encoding`) and surfaced
  in both the JSON and terminal reports, so the transcoding decision is
  itself evidence, not a hidden step. Binary content round-trips
  completely unchanged. See `benchmark/corpus/development/bench-023-utf16-charset-smuggling`.
- Fixed `SKIL-BOUNDARY-MCP-CONFIG` false-positiving on a skill reading and
  summarizing its own declared `mcp.json` for the user, indistinguishable
  from reading another agent's MCP configuration (#35). Added negative-
  context guard support to `internal/analyzer.Boundary` (previously unused
  by any boundary rule) for this.
- Fixed the remaining wide-whitespace mutation bypasses in
  `internal/analyzer/pattern.go`'s text rules (a contributor's PR fixed
  three rule IDs; this closes the same class across the rest of the
  file's multi-word phrases) and promoted wide-whitespace to a hard
  per-rule invariant in `TestMutationRobustnessOfTextRules`, alongside
  case mutations.

## 0.2.0 - 2026-08-21

- Fixed the workspace/artifact tool path-confinement check accepting
  POSIX-style rooted paths (e.g. `/tmp/escape`) as ordinary relative paths
  on Windows: `filepath.IsAbs` alone doesn't catch them there, since it
  requires a drive letter to consider a path absolute on that platform.
  Also fixed two Windows-only false test failures caused by
  `\`-vs-`/` path-separator mismatches, and pinned line endings to LF via
  `.gitattributes` so content-hash-sensitive fixtures and generated-doc
  comparisons stay byte-identical across platforms. Found and fixed while
  cutting this release's first real cross-platform CI run.
- Added a shared optional-analyzer pipeline for scan, verification,
  attestation, policy evaluation, and installation.
- Added common manifest/lock dependency inventory and deterministic SPDX 2.3
  SBOM output, plus exact Go-binary SBOMs from embedded build information.
- Added digest-guarded transactional update and uninstall operations.
- Added Linux hard-memory isolation, required native-sandbox CI, dependency
  vulnerability CI, native release builds, checksums, and OIDC attestations.
- Added a host-mediated multi-step tool gateway, Windows AppContainer/Job
  isolation, live native-OSV evidence, and release-attestation verification.
- Added canonical package validation, deterministic archives, atomic local
  installation, and `agent-skills.lock`.
- Added built-in Ed25519 signing and cryptographic policy verification for
  attestations, SLSA-v1 provenance, and external scanner evidence.
- Added concrete allowlist comparison, least-privilege warnings, complete
  behavioral assertion enforcement, and a host runtime capability gateway.
- Changed attestation/evidence-bundle/package-statement signing to sign a
  canonical JSON form (recursively key-sorted, exact-precision numeric
  literals) instead of Go's struct-declaration-order marshal, so that
  external verifiers (e.g. `skpm`, `SkillForge`) can independently validate
  a skil-produced signature from the wire JSON alone, without depending on
  skil's Go types. This changes the signed byte sequence for these types;
  signatures produced by earlier builds will not verify against this
  version and vice versa.

## 0.1.0 - 2026-07-28

- Initial Go release with secure artifact loading, static analysis, contracts,
  verification, policies, SARIF, baselines, behavioral evals, and attestations.
- Added Tree-sitter Python AST analysis, live OSV lookup, trusted-source YARA
  scanning, and a hardened OpenAI-compatible semantic provider.

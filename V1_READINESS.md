# SKIL V1 Readiness & Stability Guarantees

This document defines the normative stability commitments and readiness criteria for SKIL v1.0.0.

---

## Stability Commitments

Upon reaching v1.0.0, SKIL guarantees backward compatibility for the following interfaces and contracts:

### 1. CLI Commands & Options
- Existing command names (`skil scan`, `skil validate`, `skil lint`, `skil verify`, `skil trust`, `skil card`, `skil completeness`, `skil receipt verify`) and flags will not be removed or renamed without a major version bump.
- Exit code semantics:
  - `0`: Success / Gate Passed.
  - `1`: Security Policy Gate Failed.
  - `2`: Invalid Input / Argument Error.
  - `3`: Internal Execution Failure.

### 2. Machine-Readable Schemas
- **Security Evidence Schema v1** (`schemas/security-evidence-v1.schema.json`): Public schema for signed attestations passed to `skgate`.
- **Finding Schema** (`pkg/skil.Finding`): Fields `id`, `rule_id`, `severity`, `category`, `message`, `location`, `suppressed`.
- **Capability Schema**: Taxonomy actions, tools, domains, permissions, and MCP integrations.
- **Skill Card Schema** (`internal/card`): Machine-readable Skill Card JSON and YAML outputs.
- **SARIF v2.1.0 Export**: Full compliance with OASIS SARIF v2.1.0 specification.

### 3. Security Rules & Severities
- Rule IDs (e.g. `SKIL-SEC-001`, `SKIL-PY-001`, `SKIL-DYNAMIC-001`) remain immutable and uniquely identify finding categories.
- Severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) maintain constant ordering and risk deduction weights.

---

## V1 Production Readiness Definition of Done

- [x] Canonical responsibility boundary frozen with `skgate` and `skrun`.
- [x] Security Evidence Schema v1 versioned and validated against Draft 2020-12 meta-schema.
- [x] Direct `skil` $\rightarrow$ `skgate` cryptographic evidence interop blocking in CI.
- [x] `skrun` execution receipt verification integrated via `skil receipt verify`.
- [x] Required GitHub Actions dependencies pinned to full 40-character commit SHAs.
- [x] Formal threat model published in `THREAT_MODEL.md`.
- [x] `ExecutableIdentity` abstraction established across Python, JS/TS, Shell, MCP, and native executables.
- [x] Benchmark regression gate enforced in release validation.

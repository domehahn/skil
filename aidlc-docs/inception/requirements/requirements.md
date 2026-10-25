# Improvement and Extension Requirements

## Intent

Implement the approved improvement set from the project assessment while preserving the existing security model, public APIs, fail-closed behavior, and deterministic evidence semantics.

## Requirement groups

### R1: Explainable results

- Add a user-facing `skil explain` command.
- Explain verdict, status, findings, coverage gaps, closure limitations, analyzability, and recommended next actions.
- Support terminal and JSON output.
- Accept a previously generated scan JSON as the canonical input; optionally support scanning in a later phase.

### R2: Consistent result consumption

- Reuse existing `ScanResult` as the canonical machine-readable contract.
- Do not introduce a breaking change to `pkg/skil.ScanResult`.
- Keep exit-code semantics unchanged.

### R3: Incremental analysis foundation

- Define a digest-keyed cache boundary and cache metadata contract.
- Never reuse results when artifact, analyzer version, configuration, or relevant provider identity changes.
- Cache failures and incomplete results only when explicitly marked non-authoritative.

### R4: Control-plane roadmap

- Add a design-level implementation skeleton for continuous assurance: change detection, closure refresh, policy evaluation, attestation renewal, and runtime pin invalidation.
- Keep it opt-in and fail closed; do not add a background daemon without a separately testable lifecycle.

### R5: Reliability and quality

- Unify provider timeout/degradation policy in documentation and tests.
- Add documentation-link validation and network-independent test seams where practical.
- Document API/schema compatibility expectations.

## Non-goals for the first implementation unit

- No breaking public API changes.
- No new external network service.
- No background process or persistent database.
- No default activation of semantic providers.
- No broad CLI rewrite unrelated to the approved capabilities.

## Acceptance criteria

- `skil explain <scan.json>` produces useful terminal output and valid JSON.
- Invalid or incomplete scan input fails with an actionable input error.
- Existing tests remain compatible and new command tests cover pass, fail, unknown, and malformed input.
- A staged roadmap exists for the remaining approved improvements.

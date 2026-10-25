# Code Structure

## Repository layout

- `cmd/`: executable entrypoint.
- `internal/`: 58 non-public implementation packages spanning ingestion, analysis, assurance, evaluation, policy, supply chain, registries, MCP, telemetry, and security controls.
- `pkg/`: public Go API: domain models (`skil`), scan orchestration (`engine`), and runtime authorization (`enforcement`).
- `schemas/`: 18 JSON schemas plus Go embedding and schema tests.
- `tests/`: cross-package integration, schema, registry, security-invariant, and fixture-driven tests.
- `compat/`: ASPS taxonomy and external-scanner differential/conformance harness.
- `benchmark/`: adapters, pinned versions, runners, and evidence verification.
- `rules/`: native malware/YARA rule sources.
- `docs/`: architecture, threat model, control matrix, ADRs, changes, specifications, and operational guidance.
- `examples/`: policies, adversarial inputs, dependency reputation, and scanner-torture fixtures.

## Public domain model

`pkg/skil/models.go` defines artifacts, findings, rules, scan results, coverage, inspection work, analyzability, evidence graphs, assurance closures, budgets, and provider interfaces. `contracts.go`, `eval.go`, `evidence.go`, and `assurance.go` extend the model into declared capabilities, runtime evaluation, attestation/provenance, and assurance proofs.

## CLI organization

The CLI uses a hand-rolled top-level dispatcher with stable exit codes: 0 success, 1 gate failure, 2 input error, and 3 internal error. Major command families cover validation/lint/scan, verification/evaluation/assurance, evidence/attestation/provenance, package/install/update, policy/registry/admission, graph/trust/card, MCP/proxy/telemetry, and CI/developer utilities.

## Testing structure

Tests are colocated with packages and supplemented by integration fixtures, security invariants, schemas, ASPS conformance, external differential properties, benchmark evidence checks, and release/container workflow gates. The repository contains 425 Go files, including 195 test files.

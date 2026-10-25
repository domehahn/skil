# Reverse-Engineered Architecture

## Layering

- `cmd/skil` is the minimal executable entrypoint.
- `internal/cli` composes commands, flags, providers, reports, exit codes, and lifecycle operations.
- CLI dispatch is grouped into analysis, assurance, lifecycle, and developer command registries in `internal/cli/dispatch.go`; command handlers remain thin adapters over the existing domain operations.
- `internal/artifact` performs safe ingestion, canonicalization, archive handling, manifests, and digests.
- `internal/analyzer` contains the registry, built-in rules, AST/data-flow/security analyzers, dependency analysis, capability observation, and coverage ledgers.
- `internal/assurance`, `internal/completeness`, and `internal/evidence` aggregate findings, work completion, evidence, closure identity, and attestation projections.
- `internal/eval`, `internal/isolation`, `internal/sandbox`, `internal/runtimeproxy`, and `internal/toolgrants` implement the execution and host-gateway boundary.
- `internal/verification` compares declared contracts with observed capabilities and reviewed closure state.
- `internal/policy` evaluates explainable environment-specific decisions without scanning itself.
- `internal/packagecheck`, `internal/lockfile`, `internal/signing`, `internal/sbom`, and `internal/receipt` implement supply-chain lifecycle artifacts.
- `pkg/skil` exposes stable domain models and extension interfaces; `pkg/engine` exposes composable scanning; `pkg/enforcement` exposes runtime authorization.
- `schemas` embeds and tests versioned JSON schemas used by contracts and evidence formats.

## Main data flow

Input is loaded into an immutable canonical artifact. The artifact is scanned by independent analyzers, optionally transformed into bounded derived views, and summarized with findings, capability observations, coverage, analyzability, and inspection work. Verification compares declarations with observations. Assurance closure resolves required references and computes a canonical closure digest. Evaluation can add runtime effects. Evidence, attestations, provenance, and policy consume these results. Runtime enforcement consumes reviewed contract and digest pins, not raw scan output.

## Extension model

`pkg/skil` defines interfaces for analyzers, semantic/vulnerability/reputation/document-trust providers, signing, evidence import, and agent runtimes. `pkg/engine.Registry` wraps the internal analyzer registry. Providers are selected explicitly by CLI configuration and cannot acquire tools through their interfaces.

## Trust boundaries

- Untrusted artifact to scanner: race-resistant, bounded, non-executing ingestion.
- Scanner to optional provider: explicit opt-in, endpoint validation, visible degraded coverage.
- Skill runtime to host: structured gateway requests, contract authorization, budgets, confirmations, digest pins, and audit decisions.
- External evidence to policy: schema validation, signer/provider trust, age and digest checks.
- Registry/install to artifact: package identity, lockfile, signature, attestation, provenance, policy, and revocation checks.

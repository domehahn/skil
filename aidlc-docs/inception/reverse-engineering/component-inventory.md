# Component Inventory

| Component | Responsibility | Key evidence |
|---|---|---|
| Artifact ingestion | Safe loading, canonical manifest, archive and remote boundaries | `internal/artifact`, `internal/cli/remote.go` |
| Analyzer registry | Deterministic analyzer composition and coverage ledger | `internal/analyzer`, `pkg/engine` |
| Contract/validation | Skill schema and semantic contract validation | `internal/contracts`, `schemas` |
| Assurance/closure | Canonical closure, trust aggregation, authorization continuity, budgets | `internal/assurance`, `internal/completeness` |
| Evidence | Digest-bound projections, attestations, provenance, receipts | `internal/evidence`, `internal/receipt`, `pkg/skil` |
| Evaluation | Controlled behavioral eval and runtime observations | `internal/eval`, `internal/evalharness` |
| Isolation/gateway | Native isolation, host-mediated tools, runtime proxy and grants | `internal/isolation`, `internal/sandbox`, `internal/runtimeproxy`, `internal/toolgrants` |
| Verification | Declared-versus-observed and reviewed-closure comparison | `internal/verification` |
| Policy | Explainable allow/deny decision and trust promotion | `internal/policy` |
| Supply chain | Package lifecycle, lockfiles, signing, SBOM, provenance, revocation | `internal/packagecheck`, `internal/lockfile`, `internal/signing`, `internal/sbom`, `internal/revocation` |
| MCP/registry | MCP posture, interception, registry admission, discovery | `internal/mcp*`, `internal/registry`, `internal/discover`, `internal/cli/admission*` |
| Reports/CLI | User-facing commands, output formats, exit codes, orchestration | `internal/cli`, `internal/report`, `cmd/skil` |
| Compatibility/benchmarks | External scanner parity and reproducible measurement | `compat`, `benchmark` |

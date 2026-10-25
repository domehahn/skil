# Improvement Roadmap

## Phase 1: Explainability

Deliver `skil explain <scan.json>` for operators and CI users. It consumes the existing canonical `ScanResult`, so no second interpretation of scan findings is introduced.

## Phase 2: Incremental analysis

The first cache foundation is available through `pkg/engine.NewWithCache` and `MemoryCache`. It is keyed by artifact digest, analyzer metadata, contract, and domain filter; degraded, incomplete, budget-exceeded, and error results are never stored. Persistent cache formats and provider-specific identity remain follow-up work.

## Phase 3: Provider resilience

`internal/provider/resilience` now provides bounded retries for replayable provider requests, transient-status handling, `Retry-After` support, context cancellation, and non-retry of client errors. OSV and OpenSSF use it; semantic providers continue to degrade explicitly and remain non-retried by default because duplicate model calls can have cost and side-effect implications.

## Phase 4: CLI and compatibility

Move command families behind internal service interfaces, add output-envelope compatibility fixtures, and validate documentation links in CI.

## Phase 5: Continuous Assurance Control Plane

Implemented as the explicit one-shot command `skil continuous check`. It persists versioned state, compares artifact and closure digests, evaluates policy, marks runtime pins invalid after drift or denial, and signals when attestation refresh is required. A background daemon remains a future extension after locking, scheduling, and lifecycle behavior are proven.

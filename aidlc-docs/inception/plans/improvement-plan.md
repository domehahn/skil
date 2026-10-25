# Implementation Plan

- [x] Record requirements and preserve public API/exit-code compatibility.
- [x] Implement `skil explain` as the first user-visible improvement.
- [x] Add focused tests for explanation output and malformed input.
- [x] Document the incremental-analysis and continuous-assurance extension boundaries.
- [x] Add digest-keyed incremental cache with explicit invalidation metadata.
- [x] Add provider resilience abstraction and conformance tests.
- [x] Split CLI command families behind internal interfaces.
- [x] Add documentation-link and network-independent test gates.
- [x] Implement the opt-in Continuous Assurance Control Plane.
- [x] Add compatibility fixtures for public API and serialized result versions.

## Execution order

1. Explainability and canonical result consumption.
2. Incremental analysis/cache.
3. Provider resilience and test seams.
4. CLI modularization and compatibility gates.
5. Continuous Assurance Control Plane.

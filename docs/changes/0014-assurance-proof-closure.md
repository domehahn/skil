# Change 0014: Assurance proof and effective-verification closure

Status: implemented (additive foundation; provider-specific adapters remain incremental)

## Repository gap matrix

| Requirement | Existing implementation | Evidence | Gap | Action |
|---|---|---|---|---|
| Effective verification lifecycle | Inspection ledger, result-commit protocol, semantic degraded diagnostics | `pkg/skil/models.go`, `internal/completeness/resolution.go`, `internal/provider/semantic/degrade.go` | No shared proof requiring named transitions | Add `ControlProof`, `AssuranceStage`, and conservative scan assessment |
| Destination binding | Provider endpoint validation, metadata blocking, redirects disabled | `internal/provider/semantic/openai.go`, `provider_assure.go` | No reusable binding of provider, endpoint, model, credential scope, and config | Add `VerificationDestinationBinding` and `EffectiveInvocationEvidence` |
| Coverage and ownership | `AssuranceClosure`, inspection summary, derived-view limits | `pkg/skil/models.go`, `internal/assurance/closure.go`, `internal/derived/ownership.go` | No common universe for omitted/unsupported/failed/budget-limited subjects | Add `CoverageUniverse` and deterministic `SubjectOwnershipGraph` |
| Typed assurance dimensions | SAFE/UNSAFE/UNKNOWN and closure state | `pkg/skil/models.go`, `internal/assurance/closure.go` | Limitations are not dimension-scoped | Add dimensions and causal limitations |
| Outcome proof | Closure `Complete`, `State`, `Verified` | `internal/assurance/closure.go` | Terminal outcome can lack a typed applicability/policy proof | Add `AssuranceOutcomeProof` |
| Evidence subject binding | Dependency identity and closure digests | `pkg/skil/models.go`, `internal/evidence/attestation.go` | Findings lack a first-class occurrence identity | Add artifact/subject-bound occurrence fingerprinting and baseline target kinds |
| Analyzer attribution and maturity | Analyzer metadata and pinned benchmark support | `pkg/skil/models.go`, `benchmark/runner` | No portable attribution/maturity record | Add `AnalyzerAttribution` and `RuleMaturity` |

## Acceptance criteria and validation

- A required control cannot validate with an empty stage, evidence ID, or digest.
- An empty finding set is not execution proof; successful and failed work are distinguished by the inspection ledger.
- Destination changes, redirects, provider changes, and incomplete identity fields fail closed.
- Required omitted coverage is incomplete; explicit policy exclusion is represented separately.
- Findings from different subjects or artifact digests cannot share an occurrence fingerprint.
- Scan results expose the additive assurance report without changing legacy status/verdict compatibility.

Focused tests are in `pkg/skil/assurance_test.go` and `internal/assurance/scan_test.go`.

## Scope and residual work

This change deliberately extends existing assurance, evidence, and inspection boundaries. It does not add network calls, install dependencies, or execute analyzed artifacts. Provider adapters still need to populate `EffectiveInvocationEvidence` when external semantic verification is used; until then the scan assessment remains conservative and cannot use provider execution as proof of COMPLETE assurance.

Rollback is a source revert; serialized fields are additive and omitted when not populated.

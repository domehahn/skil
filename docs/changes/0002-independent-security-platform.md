# Change 0002: Independent native security platform

Status: completed

Owner: skil maintainers

## Requirements

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| R-01 | Independent product identity | No third-party scanner name, rule prefix, copied rule count, or compatibility claim exists in public code/docs/CLI output. |
| R-02 | Executable control traceability | Every public native control is emitted by an analyzer or explicitly marked provider-backed and has a regression test or coverage contract. |
| R-03 | Contract observation | Analyzer capability evidence, including reflective execution, participates in declared-vs-observed verification. |
| R-04 | Structured intent review | Description mismatch, context misuse, scope expansion, and implementation divergence have distinct native IDs. |
| R-05 | Portable contract input | A compact top-level contract can be parsed and normalized into the strict native least-privilege model without weakening defaults. |
| R-06 | Portable lock input | `artifact`/`sha256` aliases can be read and are normalized to native package/content digests. |
| R-07 | Native verdict | Scan output uses an independently named, documented verdict derived from `skil` policy, not a third-party scoring table. |
| R-08 | Runtime isolation | External process evaluation fails closed without an isolation provider and validates reported operations against the native enforcer. |
| R-09 | Validation | Unit, integration, race, vet, diff, and public-string checks pass. |

## Assumptions and boundaries

- Feature overlap alone is not treated as a legal conclusion.
- No third-party source code or documentation text is intentionally copied.
- Patent clearance, trademark searches, trade-dress review, and legal opinions
  are outside engineering scope and require counsel before commercial release.
- Backward compatibility for the temporary third-party-prefixed rule IDs is
  intentionally not retained because those changes were not released.

## Test matrix

| Requirement | Evidence |
| --- | --- |
| R-01 | repository-wide public-string and rule-prefix check |
| R-02 | native catalog uniqueness/implementation tests |
| R-03 | verification tests using capability evidence |
| R-04 | semantic normalization tests for four intent controls |
| R-05 | compact/native contract parsing and rejection tests |
| R-06 | native and portable lockfile fixtures |
| R-07 | risk/verdict boundary tests |
| R-08 | unsandboxed rejection and enforcer validation tests |
| R-09 | `go test`, `go test -race`, `go vet`, `git diff --check` |

## Rollback

Revert this change as one unit. Do not restore public third-party branding or an
unsandboxed runtime as a compatibility shortcut.

## Completion evidence

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `git diff --check`
- independent-identity regression and repository-wide public-string check
- native rule-list inspection confirming only the `SKIL-*` namespace

The native isolation integration test cannot enter a second macOS sandbox from
the current nested development sandbox, so it reports an explicit skip there.
Construction fails closed when the operating-system helper cannot apply its
profile. Provider-boundary, authorization, and rejection paths are covered by
the automated runtime tests.

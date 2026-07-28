# Change 0003: Production readiness

Status: implemented; external workflow runs retain environment-specific evidence

Owner: skil maintainers

## Requirements

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| R-01 | Reproducible analysis | Scan, verify, attest, policy, and install share one optional-analyzer configuration. |
| R-02 | Evidence coverage | Attestations can bind completed OSV, YARA, and semantic analysis. |
| R-03 | Runtime gate | Supported native isolation is exercised as a required Linux CI test. |
| R-04 | Resource truthfulness | Memory limits are either enforced by the provider or rejected before execution. |
| R-05 | Dependency coverage | Common manifest and lock formats are inventoried deterministically. |
| R-06 | SBOM | The CLI emits digest-bound SPDX JSON without network access. |
| R-07 | Catalog consistency | Every emitted native rule is discoverable and every advertised capability is accurate. |
| R-08 | Lifecycle | Installations can be updated, removed, and recovered without stale lock entries. |
| R-09 | Release integrity | CI runs vulnerability, SBOM, isolation, schema, race, vet, and build gates; release configuration produces checksummed artifacts. |
| R-10 | Validation | Unit, integration, race, vet, formatting, and diff checks pass. |

## Test strategy

| Requirement | Test level |
| --- | --- |
| R-01/R-02 | CLI regression and analyzer-registry unit tests |
| R-03/R-04 | provider unit tests plus required Linux integration job |
| R-05/R-06 | parser fixtures, deterministic snapshot properties, schema validation |
| R-07 | bidirectional emitted-rule/catalog and CLI contract tests |
| R-08 | install/update/remove rollback integration tests |
| R-09 | workflow syntax review and local equivalents where available |
| R-10 | full Go test, race, vet, format, and diff gates |

## Rollback

Revert this change as a unit. Installation lifecycle changes must restore both
the target directory and lockfile from the same pre-operation state.

## Validation record

Local validation covers the complete Go test suite, race detector, vet, module
integrity, release-style build and SPDX generation. Native Linux and Windows
sandboxing, the live vulnerability query, and artifact verification are
required by GitHub workflows, which retain their environment-specific evidence.

# Change 0005: Independent inspection platform expansion

Status: implemented; native YARA and online remote/OSV paths retain CI or
environment-specific evidence

Owner: skil maintainers

## Intent

Expand `skil` from a single-artifact scanner into a complete inspection
platform while preserving its vendor-neutral contracts, offline-safe defaults,
and assurance features. The implementation is original: third-party source
code, rule identifiers, prompts, rule wording, and output schemas are not
copied.

## Requirement deltas

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| R-19 | Inspection accounting | Every analyzer/file work item records a deterministic outcome and scan results expose a completeness summary. |
| R-20 | Completeness gate | A caller can require all applicable work to complete; failed or skipped work cannot produce a clear verdict. |
| R-21 | Syntax-aware data flow | Python, JavaScript, and TypeScript sources are analyzed through syntax nodes with multi-step assignment propagation. |
| R-22 | Boundary-specific controls | Native controls cover server-side request abuse, cloud metadata access, container control-plane access, agent surveillance, and mutable MCP tool identity. |
| R-23 | Collection scanning | A directory containing multiple skills can be discovered and scanned deterministically without treating the collection as one skill. |
| R-24 | Vulnerability resilience | OSV lookups support bounded batch requests, an integrity-checked cache, explicit offline mode, and visible degraded operation. |
| R-25 | Integrated malware controls | `skil` includes an independently authored conservative YARA source pack while keeping malware scanning explicitly opt-in. |
| R-26 | Scanner service | The scanner can be exposed through a bounded MCP stdio service; network transport is not enabled implicitly. |
| R-27 | Semantic separation | Semantic analysis supports independent security, intent, and quality passes plus constrained synthesis with provider-neutral structured results. |

## Compatibility and safety

- Existing commands and JSON fields remain compatible; new fields are
  additive.
- Static scanning remains offline by default.
- Remote model, vulnerability, malware-binary, and service execution remain
  explicit choices.
- Untrusted artifacts are never executed by static analyzers.
- Collection discovery rejects symlinks and preserves artifact resource
  limits.

## Validation

- Unit tests cover accounting, syntax-aware propagation, new controls,
  collection discovery, cache integrity/offline behavior, and MCP protocol
  bounds.
- `go test -race ./...`, `go vet ./...`, and `staticcheck ./...` pass.
- The platform-specific isolation package cross-compiles for Linux and Windows.

Local evidence:

- `go test -race ./...`
- `go vet ./...`
- `staticcheck ./...`
- `go mod verify`
- Windows and Linux `internal/eval` cross-compilation
- 64 repository skills discovered and scanned successfully with `scan-all`

The normal Linux CI job installs YARA and exercises the embedded pack. The
dedicated OSV job retains online advisory evidence. Remote-source integration
requires a public endpoint and therefore remains an environment-specific
integration check; local tests cover explicit consent, private-address
rejection, path confinement, size bounds, and authentication.

## Rollback

The additions are isolated behind new result fields, analyzers, flags, and
commands. Reverting this change restores the prior single-artifact behavior
without changing contracts or package formats.

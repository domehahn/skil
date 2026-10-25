# Architecture Review

## Summary

The architecture is intentionally layered around a canonical artifact and digest-bound evidence model. Public APIs are narrow and the CLI composes internal capabilities. The Go build graph has no compile-time import cycle because the repository currently builds its packages; the documented direction from public models to internal implementations is generally coherent.

## Findings

| Severity | Area | Evidence | Impact | Recommendation |
|---|---|---|---|---|
| Medium | CLI cohesion | `internal/cli` owns a very broad command dispatcher and many integrations | A change to one lifecycle or provider path can increase review and regression scope | Preserve command-family boundaries and consider extracting orchestration interfaces only when repeated coupling becomes measurable |
| Medium | Public API compatibility | `pkg/skil` is the shared model and interface package used by engine and enforcement | Model evolution can affect scanner, runtime, evidence, and third-party integrations simultaneously | Keep schema/version compatibility tests and document compatibility policy for exported types/interfaces |
| Medium | Runtime deployment coupling | Native isolation depends on OS facilities such as bubblewrap, `prlimit`, AppContainer, and Job Objects | Provider/platform support varies and unsupported combinations must remain fail-closed | Keep capability/coverage reporting explicit and retain platform-specific release gates |
| Medium | Synchronous provider calls | Semantic and vulnerability providers are invoked in analysis paths | Latency, endpoint failure, and quota behavior can affect user-facing scans | Preserve bounded timeouts, offline/cache modes, explicit degraded coverage, and provider-independent default scans |
| Low | Documentation drift | README links and repository inventory are not perfectly aligned in this checkout | Users may follow stale or missing documentation links | Add a documentation-link check to CI and reconcile missing references |
| Low | Environment-sensitive tests | Local sandbox denied loopback binds for admission and semantic-provider tests | Local validation cannot fully reproduce CI behavior | Provide a documented network-capable test profile or test-only listener abstraction for restricted environments |

## Boundary assessment

- Dependency direction is strongest at the public model boundary: `pkg/skil` contains domain contracts while `pkg/engine` and `pkg/enforcement` consume them.
- The artifact-to-analyzer-to-evidence-to-policy sequence is a clear pipeline and avoids letting policy scan or runtime enforcement infer authorization from findings alone.
- Data ownership is explicit for canonical artifacts, closure identity, evidence, policy inputs, and runtime decision records. No database or queue ownership is present in the repository.
- Cross-boundary writes are limited to generated reports, attestations, package/lock artifacts, telemetry, and runtime audit decisions; these are serialized outputs rather than shared mutable stores.
- The CLI is the main coupling hotspot, but it is an orchestration boundary rather than a domain owner.

## ADR candidates

1. Public API and schema compatibility policy: define what is stable across minor releases and how migrations are handled.
2. Provider timeout/degradation semantics: define consistent behavior across OSV, semantic, reputation, and external evidence providers.
3. Cross-platform isolation capability matrix: record which runtime guarantees are available on each supported OS and how policy gates them.
4. Documentation consistency gate: decide whether all README links must resolve in the same checkout and how generated/optional docs are represented.

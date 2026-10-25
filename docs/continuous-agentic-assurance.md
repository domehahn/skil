# Continuous Agentic Assurance

SKIL models assurance as a loop: Detect → Verify → Decide → Attest → Enforce → Observe → Detect Drift → Re-Assure. The implementation is evidence-monotonic: more uncertainty, unresolved work, authority, drift, incomplete analysis, or unverified behavior cannot increase assurance.

## Authorization and session boundaries

`internal/assurance.AuthorizationConstraint` binds principal, action, resource, scope, allow/deny effect, confirmation requirement, and provenance into a stable digest. Constraint continuity is evaluated at workspace, session, compaction, subagent, and tool/MCP boundaries as `PRESERVED`, `WEAKENED`, `LOST`, `CONFLICTING`, or `UNKNOWN`.

An `AssuranceContext` binds principal and parent principal, workspace/session, model/provider, skills, MCP endpoints, hooks, permissions, constraints/effective authority, policy, instructions, runtime capabilities, and parent/current closure identities. A derived child is never automatically verified. Security-relevant delta inputs change its closure identity; authority drift becomes an explicit limitation.

The bounded authority graph supports `DELEGATES_TO`, `CAN_INVOKE`, `AUTHORIZED_FOR`, `DENIED_FOR`, `EXECUTES`, `CONTROLS`, and `CALLS`. Transitive capability escalation is returned only for a reachable path whose edges have evidence. Graph node, edge, and depth limits fail explicitly.

## Completeness and budgets

The detailed work ledger records identity, stage, subject, artifact, analyzer, outcome, evidence, limitation, allocation, consumption, completed/remaining work, and termination reason for each planned unit. Every unit needs an accounted terminal state. An empty ledger is not complete.

Hierarchical budgets supplement, rather than replace, `skil.AnalysisBudget`. A child reservation is capped by remaining parent capacity and attributed immediately, preventing sibling over-allocation. Exhaustion remains an incomplete outcome; evidence already committed is retained.

Result commit state distinguishes result receipt, validation, evidence commit, completion receipt, and completion. Valid findings committed before malformed/truncated completion remain evidence while analysis remains incomplete.

## Behavioral and runtime verification

The original loss-of-control evaluation model varies goal pressure, constraint state, unsafe opportunity, context, and delegation. It measures unauthorized actions, boundary crossing, confirmation bypass, stop compliance, constraint retention, delegation escalation, and aggregate loss of control.

Metrics use host-observed effects. A model statement can be `OBSERVED` but cannot become `VERIFIED`. Verification requires an external observation plus observer and runtime identities. No observation is not proof that an action cannot occur; a scenario without an observation makes the suite incomplete. Untrusted programs remain confined to the existing isolated adapter and host-mediated gateway.

## Identity, discovery, and drift

`ExecutableIdentity` retains `CallableIdentity` compatibility while adding explicit resolution. Component constraints are classified as `EXACT`, `RANGE`, `FLOATING`, `LATEST`, `WILDCARD`, `UNSPECIFIED`, or `UNKNOWN`; resolved identity/version/digest participate in component identity. A changed resolution emits `MUTABLE_COMPONENT_DRIFT`. Exact known identities exit before fuzzy similarity analysis.

Local discovery includes GitHub Copilot CLI's `~/.copilot/mcp-config.json`, normalizing `local`, `http`, and `sse` transports. MCP endpoint identity binds source tool/config, name, transport, command/args or URL, TLS/auth/schema identities, and provenance. Each probed location records `COMPLETE`, `PARTIAL`, `UNSUPPORTED`, `FAILED`, or `NOT_PRESENT`. A malformed sibling cannot hide valid entries.

## Evidence, decisions, and attestation

Security projections retain evidence/finding/rule/artifact identities, location, severity, confidence, verification state, provenance, and classification across lossy summaries and handoffs. A downgrade such as `VERIFIED` → `INFERRED` is a preservation failure.

Typed facts provide a stable correlation boundary. New decision rules progress through `EXPERIMENTAL`, `SHADOW`, `BENCHMARKED`, and `ENFORCE`; benchmark identity, recall, false-positive ceiling, hard negatives, determinism, and monotonicity gate promotion.

Attestation v2 binds subject, closure, policy, graph, observer, plan, work ledger, budget policy, completeness dimensions, authorization/effective authority, optional behavioral/runtime/LoC evidence, optional honest model identity, and final decision. Missing required evidence prevents construction. Any bound change invalidates the digest. Model fingerprint fields are optional because SKIL does not claim reliable black-box provider fingerprinting.

## Known limitations and deferred integrations

- The new v2 and session/LoC primitives are library APIs; not every legacy CLI command emits v2 yet. V1 remains supported and now fails closed when closure, inspection, verification, or trust evidence is absent.
- Runtime canary strategies use the existing isolated runtime/gateway; reusable canary implementations for every requested capability remain future work. Host execution is never used as a shortcut.
- Syntax ownership currently identifies file-level languages and Markdown prose/fences with exact byte spans. Full JSON-token, YAML-node, and mixed HTML ownership is deferred to parser-backed implementations.
- Model/provider drift can bind requested/reported identities and externally supplied fingerprints, but SKIL does not infer vendor/model identity statistically.
- Competitive delta automation compares normalized same-corpus result sets. Tencent and Snyk executable adapters are deferred until stable, safely invocable output contracts can be pinned; their upstream capability changes remain radar inputs.

These limitations reduce completeness; none is interpreted as a clean result.


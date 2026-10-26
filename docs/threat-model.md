# Threat model

## Adversaries and threats

The agent is an untrusted principal. It need not be malicious: dangerous
behavior can emerge from goal optimization, autonomy, capability,
environmental opportunity, and model-dependent behavior. A prompt is guidance,
not a security boundary.

We consider a malicious skill author; compromised source, dependency, registry,
builder, or scanner; artifact substitution; direct and indirect prompt
injection; secret exfiltration; tool abuse; MCP poisoning and rug pulls;
permission escalation; malicious updates; stale attestations; forged evidence;
semantic-analyzer injection; behavioral drift; and model-dependent behavior.

Assets include user data, source code, credentials, filesystem, network, agent
memory, tools, MCP servers, organizational systems, CI/CD, and registries.

## Key mitigations

- canonical per-file and artifact digests bind evidence
- archive and input limits defend traversal and parser/resource attacks
- scanning never executes skill code or makes hidden network requests
- contracts and policies fail closed on security-relevant invalid state
- semantic requests label content untrusted and expose no tool channel
- behavioral execution is explicit, mock-only by default, and externally
  executable only through native isolation plus a host-mediated tool gateway
- adapter-owned authorization and audit claims are rejected; registered host
  tools derive operations and are checked before execution
- eval target constraints can only narrow the contract; denied operations are
  host-recorded containment violations and never reach tool execution
- task correctness and policy, capability, and containment compliance are
  independent results bound to artifact and eval-spec digests
- analysis coverage prevents a partial scan from masquerading as full assurance
- proof-carrying runtime gateways validate cryptographic operation tokens before tool execution
- dual-phase proxy checks enforce both guardrails and proof authorization, rejecting mutated arguments without reauthorization
- MCP interceptors enforce strict JSON-RPC structure, Surface Lock schemas, and operation-bound tokens, isolating blocked calls from upstream servers
- continuous re-assurance invalidates active tokens upon skill, schema, policy, capability, or provider drift
- durable host-atomic nonces prevent token replay across concurrent requests and service restarts

Residual risk includes static-analysis evasion, unknown dependencies,
compromised providers, malicious but policy-compliant behavior, TOCTOU after
verification, platform sandbox vulnerabilities, and compromised host-tool
implementations.
The local simulator proves gateway and evidence behavior, not the absence of
kernel, hypervisor, provider, or trusted-tool vulnerabilities.
Deployments must reverify digests at install time and may layer stronger
container or VM isolation around behavioral evaluation.

## Assurance invariants

The implementation and regression suite preserve these monotonic properties:

1. Later or semantic analysis may add evidence, but cannot erase a
   deterministic finding.
2. A required unsafe descendant makes the root closure unsafe.
3. A required unresolved, failed, or unanalyzed descendant cannot yield
   `SAFE`; it yields `UNKNOWN` unless another required member is unsafe.
4. Exhausting any analysis budget is explicit incomplete coverage and blocks a
   policy allow decision.
5. An attestation binds the canonical closure graph, its root and closure
   digests, state, completeness, verification status, and dependency evidence.
6. Runtime authorization rejects configured root or closure drift before
   operations and rejects unreviewed runtime dependency loads.
7. Dependency identity includes ecosystem, package/version, manifest digest,
   source kind and canonical source URL, plus payload digest when available.
8. Agent hooks, permissions, tool/MCP allowlists, bypass modes, and persistent
   state are treated as executable or privileged assurance surfaces.
9. `SAFE` is not an alias for `UNKNOWN`; missing evidence cannot increase
   assurance.
10. Parent verification never transfers automatically to a child principal.
11. Missing, weakened, or conflicting authorization constraints reduce assurance.
12. Runtime claims become `VERIFIED` only through identified external observers.
13. A malformed configuration sibling, completion envelope, or summary cannot erase valid security evidence.
14. An invalid, expired, or revoked `ExecutionAuthorization` never permits runtime execution, and single-use nonces prevent concurrent replay (`internal/receipt`).
15. Any mutation to operation target, capability, or canonical argument digest invalidates the operation authorization (`internal/receipt`).
16. Runtime drift across skill digests, MCP schemas, RAG sources, memory stores, providers, or policies invalidates affected assurance proofs and propagates immediately to dependent policy decisions (`internal/continuous`).
17. Unverified or LLM-proposed attack paths cannot be labeled `VERIFIED_EXPLOITABLE` or `VERIFIED_BLOCKED`, and inconclusive dynamic runs remain `INCONCLUSIVE` (`internal/attackpath`, `internal/redteam`).
18. A valid cryptographic signature on a portable assurance certificate never implies `SubjectSafe` or `PolicyAccepted` when the subject is `UNSAFE`, `PARTIAL`, or `UNKNOWN` (`internal/evidence`).
19. In mandatory enforcement mode, unverified, expired, replayed, or forged operations never reach tool execution callbacks (`internal/eval`, `internal/runtimeproxy`, `pkg/enforcement`).
20. Blocked, malformed, or drifted MCP requests are terminated at the interceptor and never forwarded to upstream servers (`internal/mcpinterceptor`).
21. Argument sanitization that mutates operation arguments invalidates the authorization binding and requires explicit reauthorization over the effective digest (`internal/runtimeproxy`).
22. Durable replay protection scope is explicitly reported (`host-durable` vs `process-local`), and distributed protection is never claimed without an external distributed store (`internal/receipt`).

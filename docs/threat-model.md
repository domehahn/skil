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

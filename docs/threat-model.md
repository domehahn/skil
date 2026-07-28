# Threat model

## Adversaries and threats

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
- analysis coverage prevents a partial scan from masquerading as full assurance

Residual risk includes static-analysis evasion, unknown dependencies,
compromised providers, malicious but policy-compliant behavior, TOCTOU after
verification, platform sandbox vulnerabilities, and compromised host-tool
implementations.
Deployments must reverify digests at install time and may layer stronger
container or VM isolation around behavioral evaluation.

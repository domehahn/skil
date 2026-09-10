# ADR 0026: Observer Identity and Evidence Producer Attestation

## Context
Security evidence produced during scanning or runtime monitoring must unambiguously declare *who and what observed it*. Two security reports produced by different scanner versions or policy configurations cannot be treated as equivalent evidence without an explicit, verifiable Observer Identity.

## Decision
1. Implement `ObserverIdentity` in `internal/completeness`.
2. Include machine-verifiable attributes:
   - `skil_version`: Exact SKIL CLI/library version.
   - `binary_digest`: SHA-256 digest of the running SKIL executable.
   - `policy_digest`: SHA-256 digest of active security policy rules.
   - `analyzer_set_digest`: Digest of enabled AST, YARA, and semantic analyzers.
   - `runtime_mode`: Environment mode (offline, airgapped, full).
3. Embed `ObserverIdentity` directly into Evidence Graphs, Skill Cards, and Attestations.

## Status
Accepted.

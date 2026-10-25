# Business Overview

## Product purpose

`skil` (Skill Inspector and Linter) is a vendor-neutral security, verification, and assurance framework for AI-agent skills. A skill is treated as a supply-chain artifact combining natural-language instructions, executable code, tools, permissions, dependencies, and remote systems.

The product's central business promise is to make a trust decision explainable and digest-bound. It distinguishes `SAFE`, `UNSAFE`, and `UNKNOWN`; incomplete analysis is not promoted to safety.

## Primary business transactions

1. Inspect a skill: ingest a directory, file, archive, or explicitly allowed remote source into a canonical artifact with manifests and SHA-256 identity.
2. Analyze a skill: validate contracts, lint authoring, run static analyzers, inspect dependencies, optionally use YARA/OSV/semantic providers, and record coverage and limitations.
3. Verify declared behavior: compare declared capabilities with statically observed capabilities and produce explainable mismatches.
4. Evaluate behavior: run an explicit eval contract through an isolated adapter and host-mediated gateway; record effects, violations, metrics, and trace evidence.
5. Close assurance: assemble required local and transitive references into a canonical assurance closure and closure digest.
6. Decide policy: evaluate findings, coverage, analyzability, evidence age, signatures, provenance, revocations, closure state, and runtime-assurance requirements.
7. Publish or consume evidence: create attestations, package signatures, SBOMs, provenance, lockfiles, reports, and policy decisions for CI, registries, installation, and runtime use.
8. Enforce at runtime: authorize file, network, command, secret, tool, MCP, confirmation, and budget operations through a fail-closed host gateway.

## Users and consumers

- Skill authors use linting, validation, cards, and remediation.
- Security and platform teams use scans, verification, policy, attestations, SBOMs, provenance, registry admission, and revocation.
- CI/CD systems use stable exit codes, SARIF/JSON output, GitHub Actions, gates, and release attestations.
- Agent hosts use the public engine and enforcement packages or the CLI runtime proxy/gateway.
- Researchers and maintainers use compatibility and benchmark harnesses against external scanners.

## Core business invariants

- Untrusted skill content is data, never instructions to the scanner.
- Static scanning does not execute skill code or silently access the network.
- Optional providers are explicit and their coverage is visible.
- Required unresolved, incomplete, changed, or unsafe closure members prevent a trusted result.
- Evidence is bound to exact artifact identity and scanner/provider identity.
- Runtime authorization is separate from scan findings and fails closed on unknown or drifted state.

# ADR 0016: Skill Trust Pipeline and 0-100 Trust Score Model

Status: accepted

Date: 2026-09-04

Owner: skil maintainers

## Context

Static security scanners typically evaluate AI agent skills with binary verdicts ("safe" vs "malicious"). However, enterprise governance requires continuous, multi-dimensional trust evaluation taking into account static security, authoring quality, prompt efficiency, behavioral evaluation (`Skill Lift`), cryptographic provenance, signature status, permission risk, duplicate relationships, and runtime stability.

## Decision

Implement a vendor-neutral **Skill Trust Pipeline & 0-100 Trust Score Engine** in `skil`:

1. **Multi-Domain Inputs**:
   - **Security Score (30%)**: Evaluates AST, pattern, bytecode, taint, and threat-chain findings with severity-scaled deductions.
   - **Quality Score (15%)**: Evaluates metadata completeness, instruction clarity, usage examples, and rollback strategies.
   - **Evaluation / Skill Lift (20%)**: Evaluates behavioral performance improvements (`Skill Lift %`) and `pass@k` execution stability.
   - **Provenance & Signature (15%)**: Evaluates Ed25519 DSSE signatures and SLSA build provenance attestations.
   - **Permission Risk (10%)**: Deducts points for high-risk capabilities (shell execution, credentials access, unrestricted network).
   - **Duplicate Risk (5%)**: Deducts points for exact/semantic duplicates or subset capability overlaps.
   - **Runtime Stability (5%)**: Evaluates runtime telemetry and drift signals.

2. **Trust Level Taxonomy**:
   - `VERIFIED` (Score ≥ 90, 100% clean security, signed, provenance verified)
   - `TRUSTED` (Score ≥ 80)
   - `REVIEWED` (Score ≥ 65)
   - `RESTRICTED` (Score ≥ 45)
   - `UNTRUSTED` (Score < 45)
   - `REVOKED` (Explicitly revoked artifact)

3. **CLI Commands**:
   - `skil trust <skill>` outputs comprehensive Terminal, JSON, and SARIF trust assessments with explicit point deduction accounting.

## Consequences

- Security findings are no longer evaluated in isolation; trust decisions incorporate quality, evaluation, provenance, and permission risks.
- Every score deduction is fully explainable and mapped directly to rule IDs or evidence.
- Registries and CI/CD pipelines can enforce minimum trust score thresholds before admission or installation.

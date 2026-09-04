# ADR 0018: SKIL Skill Cards & Agentic Supply Chain Control Plane

Status: accepted

Date: 2026-09-04

Owner: skil maintainers

## Context

AI agent skills combine natural language prompts, executable tools, permissions, and dependencies into agentic supply chain artifacts. To enable transparent governance, auditability, and interoperability across registries and agent runtimes, skills require a standardized, exportable governance statement analogous to Model Cards and Software Bill of Materials (SBOMs).

## Decision

Implement **SKIL Skill Cards** and an **Agentic Supply Chain Control Plane** in `skil` (`internal/card` & `skil card` CLI command):

1. **Standardized Governance Schema**:
   - Fields: Metadata (Name, Version, Digest, Repository, Commit, Builder), Capability Fingerprint (Domains, Actions, Tools, Resources, Permissions, MCP Servers), Security Verdict, Quality Rating, Context Efficiency, Evaluation / Skill Lift %, Trust Score, Trust Level, and Provenance / Signature verification status.

2. **Multi-Format Export**:
   - Machine-readable `YAML` and `JSON` formats for automated registry gates and CI/CD pipelines.
   - Human-readable GitHub Flavored `Markdown` for developer documentation and registry UI display.

3. **CLI Interface**:
   - `skil card <skill> --format yaml|markdown|json`.

## Consequences

- Skill authors, security reviewers, and platform teams have a unified, machine-readable artifact summarizing skill capabilities and trust posture.
- Skill Cards act as the governance attestation statement throughout the publishing, admission, and deployment lifecycle.


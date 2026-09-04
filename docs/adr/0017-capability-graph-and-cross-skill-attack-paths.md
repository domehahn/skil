# ADR 0017: Capability Graph & Cross-Skill Attack Path Analysis

Status: accepted

Date: 2026-09-04

Owner: skil maintainers

## Context

Analyzing skills individually cannot catch security risks that emerge when multiple skills are composed together in an agent environment. For example, a skill that reads credentials and a separate skill with unrestricted network egress are individually medium risk, but in composition create a critical data exfiltration vector (`Credential Reader -> Agent Context -> Network Egress`).

## Decision

Implement a graph-based **Capability Graph & Cross-Skill Attack Path Analysis** engine in `skil` (`internal/attackpath` & `skil graph` CLI command):

1. **Typed Graph Model**:
   - Nodes: `SKILL`, `TOOL`, `PERMISSION`, `RESOURCE`, `DATA_CLASS`, `NETWORK_TARGET`, `MCP_SERVER`.
   - Edges: `USES`, `REQUIRES`, `ACCESSES`, `PROVIDES`, `EXFILTRATES_TO`.

2. **Cross-Skill Path Correlation**:
   - Graph traversal correlates secret/credential reader skills with separate network egress skills.
   - Emits structured findings (`SKIL-ATTACK-001`) with severity `HIGH` / `CRITICAL` for composed exfiltration paths.

3. **CLI Interface**:
   - `skil graph capabilities <skills...>`: Renders capability node/edge graph stats.
   - `skil graph attack-path <skills...>`: Evaluates composed multi-skill risk.

## Consequences

- SKIL can analyze composed risk across collections of skills rather than evaluating each skill in isolation.
- Security teams can identify and block dangerous skill combinations before deployment into multi-agent systems.

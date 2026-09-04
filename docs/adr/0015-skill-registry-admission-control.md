# ADR 0015: Skill Registry Duplicate Intelligence & Admission Control

Status: accepted

Date: 2026-09-04

Owner: skil maintainers

## Context

As AI skill ecosystems scale across organizations and public registries, duplicate, near-duplicate, and redundant skills degrade developer experience, fragment maintenance efforts, and increase attack surface. Naive filename or exact string matching fails when skill text is reworded, formatted differently, or split into subsets/supersets. Conversely, aggressive blanket rejection risks blocking legitimate specialized extensions, production hardens, and domain-complementary skills.

## Decision

Implement a multi-stage **Skill Registry Duplicate Intelligence & Admission Control** subsystem in `skil` (`internal/registry` and `skil registry` CLI commands):

1. **Multi-Stage Analysis Pipeline**:
   - **Canonical SHA-256 Fingerprinting**: Path normalization (POSIX slashes), line-ending normalization (`\r\n` -> `\n`), transient file exclusion (`.git`, `.DS_Store`, build temp files), and deterministic file-tree sorting before computing SHA-256 digests.
   - **Name & Metadata Similarity**: Combined Levenshtein distance, Jaro-Winkler similarity, and Token Set ratio across titles, identifiers, tags, and summary text.
   - **Capability Extraction & Overlap**: Automated extraction of domain, actions, tools, resources, and permissions with synonym mapping (`k8s` -> `kubernetes`, `kubectl apply` -> `deploy`) and directional containment calculation (`DirectionalContainment`) to distinguish `SUBSET` from `SUPERSET`.
   - **Semantic Similarity Engine**: Provider interface supporting offline TF-IDF n-gram vectorization (`local-tfidf`) with cosine similarity, thread-safe embedding cache, and optional SaaS/LLM embedding adapters with silent offline fallback.
   - **Relationship Classification**: Ten explicit governance categories (`EXACT_DUPLICATE`, `SEMANTIC_DUPLICATE`, `HIGH_SIMILARITY`, `CAPABILITY_OVERLAP`, `SUBSET`, `SUPERSET`, `COMPLEMENTARY`, `RELATED`, `DISTINCT`, `UNKNOWN`).
   - **Admission Policy Engine**: Policy rules mapping relationships to four admission decisions (`ACCEPT`, `ACCEPT_WITH_WARNING`, `REVIEW`, `REJECT`), configurable thresholds, explicit policy suppressions (`allow` rules), and SARIF exporter (`SKIL-REG-001` .. `SKIL-REG-006`).

2. **Offline-First Guarantee**:
   - Default operations run 100% offline with zero external network or SaaS dependencies using `local-tfidf`.
   - Candidate skill content is treated strictly as untrusted data inputs, never instructions, and analyzed statically without code execution.

3. **CLI & Governance Surface**:
   - Subcommands: `skil registry check`, `index`, `update`, `list`, `search`, `similar`, and `compare`.
   - Stable Exit Codes: `0` (Admitted), `1` (Error), `2` (Rejected), `3` (Manual Review).

## Alternatives Considered

1. **Exact Hash or File Name Matching Only**: Rejected because minor rewording, white-space changes, or instruction refactoring easily bypass literal string checks.
2. **Mandatory LLM/SaaS Embedding Gate**: Rejected because it introduces network dependencies, external API cost, and operational failure modes into local and air-gapped workflows.
3. **Binary Duplicate Flag (Duplicate vs Non-Duplicate)**: Rejected because it cannot differentiate between dangerous subset duplicates and valuable complementary or superset extensions.

## Security & Privacy Impact

- Candidate skill content and prompt text are treated as untrusted data and delimited with structured XML/JSON markers to protect LLM judge passes against prompt injection.
- Analysis is strictly static; scripts, executables, or hook commands inside candidate skills are never executed during duplicate evaluation.
- All catalog and directory access enforces strict path containment.

## Consequences

- Skill registry maintainers and CI pipelines can enforce automated admission gates to keep registries clean, deduplicated, and auditable.
- Teams receive actionable guidance on whether to reject a duplicate, request integration with an existing skill, or publish a specialized extension.
- SARIF export allows seamless integration with GitHub/GitLab code scanning and governance dashboards.

# ADR 0014: Agent skill security property taxonomy

Status: accepted

## Context

`skil`'s detection corpus grew out of the external-scanner parity work and
inherited its vocabulary: property names such as "Instruction Override",
"Unrestricted Tool Access", and "Cross-Context Output" are SkillSpector
naming, several entries describe detection mechanisms rather than properties
(e.g. "Python AST AST1–AST9", "Taint Tracking", "YARA"), and there is no
stable mapping to the wider industry frameworks (OWASP Agentic Top 10 2026,
MITRE ATLAS). A flat, mixed-level list is not a durable scientific taxonomy
and does not communicate where each concept comes from.

## Decision

Adopt the four-level separation defined in
`docs/spec/agent-skill-security-properties-v1.md`:

| Level | Example |
|---|---|
| Threat / Risk | Prompt Injection |
| Security Property / Invariant | Higher-priority instructions cannot be overridden |
| Detection Mechanism | AST, taint tracking, YARA, OSV, semantic provider |
| Control / Rule | `SKIL-PI-001` |

- Top-level security-property families `SP01`..`SP14` are the canonical
  classification (instruction, goal, data, identity/authorization, tool
  safety, code execution, state/memory, inter-agent trust, supply
  chain/provenance, runtime isolation, human-agent trust, availability,
  auditability, artifact integrity).
- Every property in `compat/external-scanner/properties.yaml` carries exactly
  one `sp` family, at least one OWASP `ASI01`..`ASI10` risk, and an optional
  `atlas` technique list. The gate test `TestTaxonomyMappings` enforces this.
- Detection mechanisms are attributes of the Control level and are never
  promoted to property status.
- Not-yet-implemented taxonomy entries carry status `PROPOSED` and live in
  the spec, not in the gate corpus. The differential gate continues to
  reject `PARTIAL` and `MISSING`.

## Source hierarchy

Concept names are not mixed across layers. The taxonomy integrates:

- OWASP Top 10 for Agentic Applications 2026 (risk IDs ASI01–ASI10);
- MITRE ATLAS (technique names);
- NVIDIA SkillSpector (most original property names in the gate corpus);
- "Agent Skills in the Wild" (Liu et al., 2026) and the 2026 skill-security
  follow-ups (attention-based detection; scanner-evasion / dynamic
  detonation) as research grounding;
- MCP Security Best Practices and NIST AI RMF / Generative AI Profile as
  protocol-level and assurance-level context.

## Consequences

- Gate properties now have stable taxonomy metadata, making the corpus
  comparable to OWASP/ATLAS and future-proof against SkillSpector naming.
- New detection work can be triaged against `PROPOSED` properties (e.g.
  inter-agent trust, provenance/signing, review-to-execution integrity,
  consent laundering, failure containment, auditability) instead of an
  unstructured backlog.
- `PROPOSED` entries are explicitly outside the scanner claim; claiming
  "complete functional superset" refers to the gate corpus only.

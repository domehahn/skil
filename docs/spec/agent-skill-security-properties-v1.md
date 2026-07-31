# Agent Skill Security Properties Specification v1.0

Status: draft · Owner: platform-engineering · Last updated: 2026-07-31

This specification defines the security-property taxonomy that `skil` uses to
classify, detect, and verify the security of agent skill artifacts (`SKILL.md`,
scripts, references, assets, and MCP manifests). The canonical taxonomy is the
Agent Skill Security Properties Specification (ASPS) v1.0 in
`compat/asps/ASPS-v1.0.md`, machine-read from `compat/asps/asps-registry.json`.
`compat/external-scanner/properties.yaml` is the gate-enforced catalog of the
implemented detection corpus, keyed to the same ASPS IDs.

## 1. Purpose

Provide a stable, scientifically-grounded vocabulary for agent skill security
that:

1. separates **what can go wrong** (threat) from **what must hold**
   (security property) from **how we check it** (detection mechanism) from
   **the concrete implementation** (control/rule);
2. maps every gate property to an **ASPS domain** (ASP-01–ASP-15), an
   **OWASP Agentic Top 10 2026** risk (ASI01–ASI10), an **OWASP LLM Top 10**
   risk (LLM01–LLM10), and — where one exists — a **MITRE ATLAS** technique;
3. tracks proposed properties that are part of the taxonomy but **not yet
   implemented** (status `NEW`/`PROPOSED`), so the specification remains the
   long-term research target while the scanner gate stays honest about what
   is implemented.

## 2. Terminology and levels

| Level | Question | Example |
|---|---|---|
| **Threat / Risk** | What can go wrong? | Prompt injection; tool misuse; privilege abuse |
| **Security Property / Invariant** | What must hold? | Higher-priority instructions cannot be overridden; `C(child) ⊆ C(parent)` |
| **Detection Mechanism** | How do we check the property? | Python AST walk, taint tracking, YARA, reputation provider, semantic provider, structured manifest analysis |
| **Control / Rule** | Concrete scanner implementation | `SKIL-PI-001`, `SKIL-TAINT-NETWORK`, `SKIL-MCP-002` |

Detection mechanisms are deliberately **not** security properties. Taint
tracking, AST analysis, YARA, OSV, and shell analysis are how `skil` verifies
a property; they are cross-cutting and must not be conflated with the
property itself.

## 3. Alignment with external frameworks

| Framework | Role | Relation to this spec |
|---|---|---|
| OWASP Top 10 for Agentic Applications 2026 | Risk classification | Every property maps to ASI01–ASI10 |
| OWASP Top 10 for LLM Applications 2025 | Risk classification | Every property maps to LLM01–LLM10 where applicable |
| MITRE ATLAS | Attacker technique catalog | Every mapped property references a technique name where applicable |
| Reference scanner corpus | Tool/vendor corpus | 64 vulnerability patterns / 16 categories; source of most original property names |
| "Agent Skills in the Wild" (Liu et al., 2026) | Empirical foundation | 14 patterns / 4 categories derived from 31,132 skills |
| MCP Security Best Practices | Protocol-level guidance | Authorization and trust-boundary properties (ASP-04, ASP-08) |
| NIST AI RMF + Generative AI Profile | Risk-management / assurance framework | Governs how properties are operationalized, not their taxonomy |

### OWASP Agentic Top 10 2026 (ASI01–ASI10)

| ID | Risk |
|---|---|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse & Exploitation |
| ASI03 | Identity & Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

### OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10)

| ID | Risk |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

## 4. Top-level security-property families

The canonical taxonomy is ASPS v1.0 (`compat/asps/asps-registry.json`),
organized into 15 domains. Each domain maps to OWASP Agentic Top 10 2026
risks and (where applicable) MITRE ATLAS techniques:

| Domain | Purpose | OWASP Agentic |
|---|---|---|
| **ASP-01 Instruction & Goal Integrity** | Schützt Instruktionshierarchie, autorisierten Auftrag und semantische Steuerung des Agenten. | `ASI01 ⊗ ASI09 ⊗ ASI10` |
| **ASP-02 Discovery, Metadata & Selection Integrity** | Schützt Admission, Retrieval und Planner-Auswahl vor Metadaten-, Ranking- und Reputationsmanipulation. | `ASI01 ⊗ ASI04 ⊗ ASI09` |
| **ASP-03 Data Confidentiality & Privacy** | Begrenzt Zugriff, Nutzung, Speicherung und Übertragung sensitiver Daten auf den legitim benötigten Umfang. | `ASI01 ⊗ ASI02 ⊗ ASI03 ⊗ ASI06 ⊗ ASI07` |
| **ASP-04 Identity, Authorization & Consent** | Sichert nicht-menschliche Identitäten, Berechtigungen, Delegation, Token-Grenzen und Zustimmung. | `ASI02 ⊗ ASI03 ⊗ ASI07` |
| **ASP-05 Tool, Capability & Agency Safety** | Begrenzt Tool-Nutzung, Parameter, Komposition und autonome Seiteneffekte. | `ASI02 ⊗ ASI03 ⊗ ASI05 ⊗ ASI10` |
| **ASP-06 Code Execution & Information-Flow Safety** | Schützt Interpreter-, Prozess-, Shell- und Output-Grenzen und erzwingt nachvollziehbaren Datenfluss. | `ASI02 ⊗ ASI05` |
| **ASP-07 Memory, State & Persistence Integrity** | Schützt persistente und temporäre Zustände vor Vergiftung, Übernahme, Überfüllung und unerlaubter Lebensdauer. | `ASI06 ⊗ ASI10` |
| **ASP-08 Inter-Agent & Delegation Security** | Sichert Agent-zu-Agent-Kommunikation, Delegation und zusammengesetzte Workflows. | `ASI03 ⊗ ASI07 ⊗ ASI08 ⊗ ASI10` |
| **ASP-09 Supply Chain, Provenance & Artifact Integrity** | Sichert Publisher, Signatur, Version, Update und Review-to-Execution-Kontinuität des Skill-Artefakts. | `ASI04 ⊗ ASI10` |
| **ASP-10 MCP & Integration Protocol Security** | Überträgt Skill-Sicherheitsinvarianten auf MCP-Metadaten, Tool-Identitäten, OAuth und lokale Integrationen. | `ASI02 ⊗ ASI03 ⊗ ASI04 ⊗ ASI07` |
| **ASP-11 Network, Filesystem & Runtime Boundary Security** | Schützt Host-, Netzwerk-, Container- und Nachbar-Skill-Grenzen. | `ASI02 ⊗ ASI03 ⊗ ASI05` |
| **ASP-12 Resource, Availability & Failure Containment** | Begrenzt Kosten, Endlosschleifen, Ressourcenverbrauch und kaskadierende Fehlwirkungen. | `ASI02 ⊗ ASI08 ⊗ ASI10` |
| **ASP-13 Human-Agent Trust & Safety** | Schützt Nutzer vor Täuschung, Consent-Laundering, gefährlichen Operationszielen und unkritischem Vertrauen in Agentenausgaben. | `ASI01 ⊗ ASI02 ⊗ ASI09 ⊗ ASI10` |
| **ASP-14 Auditability, Observability & Accountability** | Macht Skill-Entscheidungen und Wirkungen sicherheitsrelevant nachvollziehbar, ohne private Chain-of-Thought zu verlangen. | `ASI03 ⊗ ASI07 ⊗ ASI08 ⊗ ASI10` |
| **ASP-15 Dependency, Package & Container Supply-Chain Security** | Behandelt klassische Software-Supply-Chain-Risiken innerhalb von Skills als eigenständige Properties statt als Analyzer-Namen. | `ASI04 ⊗ ASI05` |

## 5. Gate corpus (implemented properties)## 5. Gate corpus (implemented properties)

Source of truth: `compat/asps/asps-registry.json` (ASPS v1.0 taxonomy, 120
properties across 15 domains); the machine-readable gate corpus in
`compat/external-scanner/properties.yaml` is keyed to ASPS property IDs and
tracks coverage per fixture (173 fixture entries). Property-level status
values: `IMPLEMENTED` (covered by native rules), `PARTIAL` (bounded coverage),
`NEW` (ASPS taxonomy entry, not yet implemented in the gate corpus),
`PROVIDER_BACKED` (requires a runtime provider, excluded from the offline CI
gate). Fixture-level status values: `FULL` (implemented and gate-tested),
`DIFFERENT_BY_DESIGN` (deliberately not a scanner rule; covered by the
verification layer), `PROVIDER_BACKED`. The differential gate rejects
`PARTIAL` and `MISSING`.

| Property | Domain | OWASP | ATLAS | Status |
|---|---|---|---|---|
| ASP-01.01 | ASP-01 · Instruction & Goal Integrity | ASI01, ASI09, ASI10 | LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-01.02 | ASP-01 · Instruction & Goal Integrity | ASI01, ASI09, ASI10 | LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-01.03 | ASP-01 · Instruction & Goal Integrity | ASI01, ASI09, ASI10 | LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-01.04 | ASP-01 · Instruction & Goal Integrity | ASI01, ASI09, ASI10 | LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-01.05 | ASP-01 · Instruction & Goal Integrity | ASI01, ASI09, ASI10 | LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-01.06 | ASP-01 · Instruction & Goal Integrity | ASI01, ASI09, ASI10 | LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration | PARTIAL |
| ASP-01.07 | ASP-01 · Instruction & Goal Integrity | ASI01, ASI09, ASI10 | LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-01.08 | ASP-01 · Instruction & Goal Integrity | ASI01, ASI09, ASI10 | LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration | PARTIAL |
| ASP-02.01 | ASP-02 · Discovery, Metadata & Selection Integrity | ASI01, ASI04, ASI09 | AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application | NEW |
| ASP-02.02 | ASP-02 · Discovery, Metadata & Selection Integrity | ASI01, ASI04, ASI09 | AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application | PARTIAL |
| ASP-02.03 | ASP-02 · Discovery, Metadata & Selection Integrity | ASI01, ASI04, ASI09 | AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application | IMPLEMENTED |
| ASP-02.04 | ASP-02 · Discovery, Metadata & Selection Integrity | ASI01, ASI04, ASI09 | AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application | IMPLEMENTED |
| ASP-02.05 | ASP-02 · Discovery, Metadata & Selection Integrity | ASI01, ASI04, ASI09 | AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application | NEW |
| ASP-02.06 | ASP-02 · Discovery, Metadata & Selection Integrity | ASI01, ASI04, ASI09 | AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application | PARTIAL |
| ASP-02.07 | ASP-02 · Discovery, Metadata & Selection Integrity | ASI01, ASI04, ASI09 | AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application | NEW |
| ASP-02.08 | ASP-02 · Discovery, Metadata & Selection Integrity | ASI01, ASI04, ASI09 | AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application | PARTIAL |
| ASP-03.01 | ASP-03 · Data Confidentiality & Privacy | ASI01, ASI02, ASI03, ASI06, ASI07 | Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-03.02 | ASP-03 · Data Confidentiality & Privacy | ASI01, ASI02, ASI03, ASI06, ASI07 | Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-03.03 | ASP-03 · Data Confidentiality & Privacy | ASI01, ASI02, ASI03, ASI06, ASI07 | Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting | PARTIAL |
| ASP-03.04 | ASP-03 · Data Confidentiality & Privacy | ASI01, ASI02, ASI03, ASI06, ASI07 | Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting | PARTIAL |
| ASP-03.05 | ASP-03 · Data Confidentiality & Privacy | ASI01, ASI02, ASI03, ASI06, ASI07 | Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-03.06 | ASP-03 · Data Confidentiality & Privacy | ASI01, ASI02, ASI03, ASI06, ASI07 | Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-03.07 | ASP-03 · Data Confidentiality & Privacy | ASI01, ASI02, ASI03, ASI06, ASI07 | Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting | NEW |
| ASP-03.08 | ASP-03 · Data Confidentiality & Privacy | ASI01, ASI02, ASI03, ASI06, ASI07 | Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting | PARTIAL |
| ASP-04.01 | ASP-04 · Identity, Authorization & Consent | ASI02, ASI03, ASI07 | Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-04.02 | ASP-04 · Identity, Authorization & Consent | ASI02, ASI03, ASI07 | Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-04.03 | ASP-04 · Identity, Authorization & Consent | ASI02, ASI03, ASI07 | Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration | PARTIAL |
| ASP-04.04 | ASP-04 · Identity, Authorization & Consent | ASI02, ASI03, ASI07 | Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration | IMPLEMENTED |
| ASP-04.05 | ASP-04 · Identity, Authorization & Consent | ASI02, ASI03, ASI07 | Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration | NEW |
| ASP-04.06 | ASP-04 · Identity, Authorization & Consent | ASI02, ASI03, ASI07 | Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration | NEW |
| ASP-04.07 | ASP-04 · Identity, Authorization & Consent | ASI02, ASI03, ASI07 | Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration | NEW |
| ASP-04.08 | ASP-04 · Identity, Authorization & Consent | ASI02, ASI03, ASI07 | Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration | NEW |
| ASP-05.01 | ASP-05 · Tool, Capability & Agency Safety | ASI02, ASI03, ASI05, ASI10 | AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host | IMPLEMENTED |
| ASP-05.02 | ASP-05 · Tool, Capability & Agency Safety | ASI02, ASI03, ASI05, ASI10 | AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host | IMPLEMENTED |
| ASP-05.03 | ASP-05 · Tool, Capability & Agency Safety | ASI02, ASI03, ASI05, ASI10 | AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host | PARTIAL |
| ASP-05.04 | ASP-05 · Tool, Capability & Agency Safety | ASI02, ASI03, ASI05, ASI10 | AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host | IMPLEMENTED |
| ASP-05.05 | ASP-05 · Tool, Capability & Agency Safety | ASI02, ASI03, ASI05, ASI10 | AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host | IMPLEMENTED |
| ASP-05.06 | ASP-05 · Tool, Capability & Agency Safety | ASI02, ASI03, ASI05, ASI10 | AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host | PARTIAL |
| ASP-05.07 | ASP-05 · Tool, Capability & Agency Safety | ASI02, ASI03, ASI05, ASI10 | AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host | PARTIAL |
| ASP-05.08 | ASP-05 · Tool, Capability & Agency Safety | ASI02, ASI03, ASI05, ASI10 | AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host | PARTIAL |
| ASP-06.01 | ASP-06 · Code Execution & Information-Flow Safety | ASI02, ASI05 | Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation | IMPLEMENTED |
| ASP-06.02 | ASP-06 · Code Execution & Information-Flow Safety | ASI02, ASI05 | Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation | IMPLEMENTED |
| ASP-06.03 | ASP-06 · Code Execution & Information-Flow Safety | ASI02, ASI05 | Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation | IMPLEMENTED |
| ASP-06.04 | ASP-06 · Code Execution & Information-Flow Safety | ASI02, ASI05 | Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation | IMPLEMENTED |
| ASP-06.05 | ASP-06 · Code Execution & Information-Flow Safety | ASI02, ASI05 | Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation | IMPLEMENTED |
| ASP-06.06 | ASP-06 · Code Execution & Information-Flow Safety | ASI02, ASI05 | Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation | IMPLEMENTED |
| ASP-06.07 | ASP-06 · Code Execution & Information-Flow Safety | ASI02, ASI05 | Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation | IMPLEMENTED |
| ASP-06.08 | ASP-06 · Code Execution & Information-Flow Safety | ASI02, ASI05 | Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation | PARTIAL |
| ASP-07.01 | ASP-07 · Memory, State & Persistence Integrity | ASI06, ASI10 | AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication | IMPLEMENTED |
| ASP-07.02 | ASP-07 · Memory, State & Persistence Integrity | ASI06, ASI10 | AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication | IMPLEMENTED |
| ASP-07.03 | ASP-07 · Memory, State & Persistence Integrity | ASI06, ASI10 | AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication | PARTIAL |
| ASP-07.04 | ASP-07 · Memory, State & Persistence Integrity | ASI06, ASI10 | AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication | IMPLEMENTED |
| ASP-07.05 | ASP-07 · Memory, State & Persistence Integrity | ASI06, ASI10 | AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication | IMPLEMENTED |
| ASP-07.06 | ASP-07 · Memory, State & Persistence Integrity | ASI06, ASI10 | AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication | NEW |
| ASP-07.07 | ASP-07 · Memory, State & Persistence Integrity | ASI06, ASI10 | AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication | NEW |
| ASP-07.08 | ASP-07 · Memory, State & Persistence Integrity | ASI06, ASI10 | AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication | NEW |
| ASP-08.01 | ASP-08 · Inter-Agent & Delegation Security | ASI03, ASI07, ASI08, ASI10 | AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning | NEW |
| ASP-08.02 | ASP-08 · Inter-Agent & Delegation Security | ASI03, ASI07, ASI08, ASI10 | AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning | NEW |
| ASP-08.03 | ASP-08 · Inter-Agent & Delegation Security | ASI03, ASI07, ASI08, ASI10 | AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning | NEW |
| ASP-08.04 | ASP-08 · Inter-Agent & Delegation Security | ASI03, ASI07, ASI08, ASI10 | AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning | NEW |
| ASP-08.05 | ASP-08 · Inter-Agent & Delegation Security | ASI03, ASI07, ASI08, ASI10 | AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning | PARTIAL |
| ASP-08.06 | ASP-08 · Inter-Agent & Delegation Security | ASI03, ASI07, ASI08, ASI10 | AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning | PARTIAL |
| ASP-08.07 | ASP-08 · Inter-Agent & Delegation Security | ASI03, ASI07, ASI08, ASI10 | AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning | NEW |
| ASP-08.08 | ASP-08 · Inter-Agent & Delegation Security | ASI03, ASI07, ASI08, ASI10 | AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning | NEW |
| ASP-09.01 | ASP-09 · Supply Chain, Provenance & Artifact Integrity | ASI04, ASI10 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | NEW |
| ASP-09.02 | ASP-09 · Supply Chain, Provenance & Artifact Integrity | ASI04, ASI10 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | NEW |
| ASP-09.03 | ASP-09 · Supply Chain, Provenance & Artifact Integrity | ASI04, ASI10 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | NEW |
| ASP-09.04 | ASP-09 · Supply Chain, Provenance & Artifact Integrity | ASI04, ASI10 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | NEW |
| ASP-09.05 | ASP-09 · Supply Chain, Provenance & Artifact Integrity | ASI04, ASI10 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | NEW |
| ASP-09.06 | ASP-09 · Supply Chain, Provenance & Artifact Integrity | ASI04, ASI10 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | PARTIAL |
| ASP-09.07 | ASP-09 · Supply Chain, Provenance & Artifact Integrity | ASI04, ASI10 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | PARTIAL |
| ASP-09.08 | ASP-09 · Supply Chain, Provenance & Artifact Integrity | ASI04, ASI10 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | PARTIAL |
| ASP-10.01 | ASP-10 · MCP & Integration Protocol Security | ASI02, ASI03, ASI04, ASI07 | AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-10.02 | ASP-10 · MCP & Integration Protocol Security | ASI02, ASI03, ASI04, ASI07 | AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting | PARTIAL |
| ASP-10.03 | ASP-10 · MCP & Integration Protocol Security | ASI02, ASI03, ASI04, ASI07 | AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-10.04 | ASP-10 · MCP & Integration Protocol Security | ASI02, ASI03, ASI04, ASI07 | AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-10.05 | ASP-10 · MCP & Integration Protocol Security | ASI02, ASI03, ASI04, ASI07 | AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting | PARTIAL |
| ASP-10.06 | ASP-10 · MCP & Integration Protocol Security | ASI02, ASI03, ASI04, ASI07 | AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting | NEW |
| ASP-10.07 | ASP-10 · MCP & Integration Protocol Security | ASI02, ASI03, ASI04, ASI07 | AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting | NEW |
| ASP-10.08 | ASP-10 · MCP & Integration Protocol Security | ASI02, ASI03, ASI04, ASI07 | AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting | NEW |
| ASP-11.01 | ASP-11 · Network, Filesystem & Runtime Boundary Security | ASI02, ASI03, ASI05 | Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting | PARTIAL |
| ASP-11.02 | ASP-11 · Network, Filesystem & Runtime Boundary Security | ASI02, ASI03, ASI05 | Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-11.03 | ASP-11 · Network, Filesystem & Runtime Boundary Security | ASI02, ASI03, ASI05 | Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-11.04 | ASP-11 · Network, Filesystem & Runtime Boundary Security | ASI02, ASI03, ASI05 | Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-11.05 | ASP-11 · Network, Filesystem & Runtime Boundary Security | ASI02, ASI03, ASI05 | Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-11.06 | ASP-11 · Network, Filesystem & Runtime Boundary Security | ASI02, ASI03, ASI05 | Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-11.07 | ASP-11 · Network, Filesystem & Runtime Boundary Security | ASI02, ASI03, ASI05 | Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-11.08 | ASP-11 · Network, Filesystem & Runtime Boundary Security | ASI02, ASI03, ASI05 | Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting | IMPLEMENTED |
| ASP-12.01 | ASP-12 · Resource, Availability & Failure Containment | ASI02, ASI08, ASI10 | AI Agent Tool Invocation | IMPLEMENTED |
| ASP-12.02 | ASP-12 · Resource, Availability & Failure Containment | ASI02, ASI08, ASI10 | AI Agent Tool Invocation | IMPLEMENTED |
| ASP-12.03 | ASP-12 · Resource, Availability & Failure Containment | ASI02, ASI08, ASI10 | AI Agent Tool Invocation | PARTIAL |
| ASP-12.04 | ASP-12 · Resource, Availability & Failure Containment | ASI02, ASI08, ASI10 | AI Agent Tool Invocation | NEW |
| ASP-12.05 | ASP-12 · Resource, Availability & Failure Containment | ASI02, ASI08, ASI10 | AI Agent Tool Invocation | NEW |
| ASP-12.06 | ASP-12 · Resource, Availability & Failure Containment | ASI02, ASI08, ASI10 | AI Agent Tool Invocation | NEW |
| ASP-12.07 | ASP-12 · Resource, Availability & Failure Containment | ASI02, ASI08, ASI10 | AI Agent Tool Invocation | PARTIAL |
| ASP-12.08 | ASP-12 · Resource, Availability & Failure Containment | ASI02, ASI08, ASI10 | AI Agent Tool Invocation | NEW |
| ASP-13.01 | ASP-13 · Human-Agent Trust & Safety | ASI01, ASI02, ASI09, ASI10 | AI Agent Clickbait, LLM Jailbreak | PARTIAL |
| ASP-13.02 | ASP-13 · Human-Agent Trust & Safety | ASI01, ASI02, ASI09, ASI10 | AI Agent Clickbait, LLM Jailbreak | PARTIAL |
| ASP-13.03 | ASP-13 · Human-Agent Trust & Safety | ASI01, ASI02, ASI09, ASI10 | AI Agent Clickbait, LLM Jailbreak | PARTIAL |
| ASP-13.04 | ASP-13 · Human-Agent Trust & Safety | ASI01, ASI02, ASI09, ASI10 | AI Agent Clickbait, LLM Jailbreak | PARTIAL |
| ASP-13.05 | ASP-13 · Human-Agent Trust & Safety | ASI01, ASI02, ASI09, ASI10 | AI Agent Clickbait, LLM Jailbreak | IMPLEMENTED |
| ASP-13.06 | ASP-13 · Human-Agent Trust & Safety | ASI01, ASI02, ASI09, ASI10 | AI Agent Clickbait, LLM Jailbreak | IMPLEMENTED |
| ASP-13.07 | ASP-13 · Human-Agent Trust & Safety | ASI01, ASI02, ASI09, ASI10 | AI Agent Clickbait, LLM Jailbreak | IMPLEMENTED |
| ASP-13.08 | ASP-13 · Human-Agent Trust & Safety | ASI01, ASI02, ASI09, ASI10 | AI Agent Clickbait, LLM Jailbreak | IMPLEMENTED |
| ASP-14.01 | ASP-14 · Auditability, Observability & Accountability | ASI03, ASI07, ASI08, ASI10 | — | NEW |
| ASP-14.02 | ASP-14 · Auditability, Observability & Accountability | ASI03, ASI07, ASI08, ASI10 | — | NEW |
| ASP-14.03 | ASP-14 · Auditability, Observability & Accountability | ASI03, ASI07, ASI08, ASI10 | — | PARTIAL |
| ASP-14.04 | ASP-14 · Auditability, Observability & Accountability | ASI03, ASI07, ASI08, ASI10 | — | NEW |
| ASP-14.05 | ASP-14 · Auditability, Observability & Accountability | ASI03, ASI07, ASI08, ASI10 | — | NEW |
| ASP-14.06 | ASP-14 · Auditability, Observability & Accountability | ASI03, ASI07, ASI08, ASI10 | — | PARTIAL |
| ASP-14.07 | ASP-14 · Auditability, Observability & Accountability | ASI03, ASI07, ASI08, ASI10 | — | NEW |
| ASP-14.08 | ASP-14 · Auditability, Observability & Accountability | ASI03, ASI07, ASI08, ASI10 | — | PARTIAL |
| ASP-15.01 | ASP-15 · Dependency, Package & Container Supply-Chain Security | ASI04, ASI05 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | IMPLEMENTED |
| ASP-15.02 | ASP-15 · Dependency, Package & Container Supply-Chain Security | ASI04, ASI05 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | PROVIDER_BACKED |
| ASP-15.03 | ASP-15 · Dependency, Package & Container Supply-Chain Security | ASI04, ASI05 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | IMPLEMENTED |
| ASP-15.04 | ASP-15 · Dependency, Package & Container Supply-Chain Security | ASI04, ASI05 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | PROVIDER_BACKED |
| ASP-15.05 | ASP-15 · Dependency, Package & Container Supply-Chain Security | ASI04, ASI05 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | NEW |
| ASP-15.06 | ASP-15 · Dependency, Package & Container Supply-Chain Security | ASI04, ASI05 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | NEW |
| ASP-15.07 | ASP-15 · Dependency, Package & Container Supply-Chain Security | ASI04, ASI05 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | PARTIAL |
| ASP-15.08 | ASP-15 · Dependency, Package & Container Supply-Chain Security | ASI04, ASI05 | AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation | IMPLEMENTED |
## 6. Proposed gap properties

Status `PROPOSED`: part of the taxonomy, **not yet implemented** and **not
part of the gate corpus**. Grouped by ASPS domain. Detection mechanism is the
proposed verification approach. IDs are proposal-local references; promoted
properties receive canonical `ASP-xx.yy` IDs in the registry.

### ASP-01 · Instruction & Goal Integrity

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP02.3 | Goal Preservation Violation | `effective_goal ⊆ authorized_goal` | Planning derives subgoals that leave the authorized scope | Semantic contract check + plan/goal diff | ASI01 |
| SP02.4 | Control Avoidance | operative controls (monitoring, approval, sandbox, policy, shutdown) are not evaded | Agent actively routes around operational controls | Pattern + behavior-in-sandbox evidence | ASI10 |
| SP02.5 | Shutdown / Revocation Resistance | `revoke(tool) ⇒ future_use(tool) = false` | Capability continues to be used or reconstructed after revocation | Enforcement-layer capability revocation audit | ASI10 |

### ASP-03 · Data Confidentiality & Privacy

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP03.6 | Data Minimization | `required_data ⊆ available_data` | Skill reads more than its task requires | Read-scope analysis against declared task contract | ASI02 |
| SP03.7 | Purpose Limitation | `use(data, P₁) ⇒ ¬use(data, P₂)` for distinct purposes | Data obtained for one purpose reused for telemetry/training | Semantic usage-flow analysis + declared purpose | ASI01 |
| SP03.8 | Unauthorized Retention / Retention Bound | `persistence ⊆ authorized_retention` | Legitimate data persisted beyond need (distinct from memory poisoning) | Persistence-site analysis + declared retention policy | ASI06 |

### ASP-04 · Identity, Authorization & Consent

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP04.4 | Delegated Credential Scope | `scope(delegated) ⊆ scope(required)` | OAuth/API credential with broader scope than needed | Credential-scope static analysis + contract check | ASI03 |
| SP04.5 | Credential Delegation Abuse | `credential_audience = authorized_audience` | User credential forwarded through agent to untrusted MCP/tool | Trust-boundary taint for credential objects | ASI03 |
| SP04.6 | Non-Human Identity Lifecycle | credential lifetime/scope/audience bound; non-transferable | Long-lived, unscoped machine identities (service accounts, MCP creds, cloud roles) | Identity manifest + lifecycle policy verification | ASI03 |

### ASP-05 · Tool, Capability & Agency Safety

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP05.8 | Trigger Collision Post-Review | reviewed trigger set remains shadow-free across updates | Updated skill shadows a new built-in command | Trigger lock-diff against built-in command table | ASI02 |
| SP05.9 | Capability-Declaration Drift | `capabilities_declared ⊇ capabilities_used` continuously | Post-review code adds capability without manifest update | Continuous contract verification (skil verify) | ASI03 |

### ASP-08 · Inter-Agent & Delegation Security

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP08.5 | Agent Identity Spoofing | `asserted_origin = authenticated_origin` | Skill claims an action/message originated from a trusted agent | Origin assertion validation in inter-agent channels | ASI07 |
| SP08.6 | Cross-Agent Trust Escalation (Confused Deputy) | delegation does not increase effective rights | Low-privilege agent reaches a high-privilege deputy | Delegation-graph rights analysis | ASI03/ASI07 |
| SP08.7 | Delegation Chain Scope Invariance | `C(child) ⊆ C(parent) ∩ C(delegated)` | Scope loss/expansion along a delegation chain | Chain-scope propagation analysis | ASI07 |
| SP08.8 | Agent Communication Integrity | agent output entering another instruction context is integrity-checked and provenance-labeled | Injected agent response promoted to trusted instruction | Cross-context taint + provenance labeling | ASI07 |
| SP08.9 | Failure Containment | a failure in one skill does not propagate unchecked | Cascading failure through trusting agents | Failure blast-radius analysis + isolation config | ASI08 |
| SP08.10 | Trust Propagation Bound | `unverified_output` remains untrusted across hops | Trust accumulated over multiple hops | Multi-hop trust-tracking (output taint) | ASI08 |

### ASP-09 · Supply Chain, Provenance & Artifact Integrity

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP09.9 | Provenance Authenticity | `publisher = expected_publisher` | Malicious artifact published under a spoofed/expected publisher | Publisher-key verification | ASI04 |
| SP09.10 | Skill Provenance (chain of custody) | every edge (author→repo→build→release→marketplace→install) authenticated | Untrusted insertion anywhere in the chain | Provenance attestation chain (SLSA-style) | ASI04 |
| SP09.11 | Artifact Integrity | `hash(installed) = hash(reviewed)` | Installed skill differs from the reviewed one | Whole-directory digest + signature (e.g. `skill.oms.sig`) | ASI04 |
| SP09.12 | Version Integrity | version label binds to the reviewed artifact | Label/artifact mismatch | Signed version attestation | ASI04 |
| SP09.13 | Update Integrity | update path is authenticated end-to-end | Unauthenticated or swapped update content | Update policy + signature check | ASI04 |
| SP09.14 | Review-to-Execution Integrity (Post-Scan Mutation / TOCTOU) | executed artifact is bound to the reviewed version | Artifact mutates between scan and execution (e.g. runtime payload fetch) | Runtime-rebinding check + execution-time digest pinning | ASI04 |
| SP09.15 | Runtime Dependency Integrity | `runtime_artifact ∈ reviewed_closure` | `curl latest.sh`, `requests.get(url)` introduce behavior at runtime | Dynamic-dependency resolution analysis + network allowlist | ASI04 |
| SP09.16 | Ownership Transfer | ownership changes are authenticated and re-attested | Transfer re-assigns trust implicitly | Transfer audit + re-attestation gate | ASI04 |
| SP09.17 | Revocation | `revoke(publisher/skill) ⇒ future_use = false` | Revoked skill continues to be installed/executed | Registry revocation propagation | ASI04 |

### ASP-13 · Human-Agent Trust & Safety

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP11.5 | Approval Manipulation | approval requests represent true risk | "Click approve" framing for destructive operations | Approval-prompt semantic check | ASI09 |
| SP11.6 | Consent Laundering | `consent(A) ⇏ consent(B)` | One consent interpreted as permission for broader data use | Consent-scope contract analysis | ASI09 |
| SP11.7 | Deceptive Risk Framing | permission necessity is not misrepresented | "This permission is required" when not required | Necessity justification validation | ASI09 |

### ASP-12 · Resource, Availability & Failure Containment

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP12.4 | Action Reversibility | destructive actions follow `stage → review → commit` | Irreversible production mutation without review | Action-class policy + reversibility gate | ASI08 |

### ASP-14 · Auditability, Observability & Accountability

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP13.1 | Action Attribution | every relevant action traceable `user→agent→skill→tool→parameters→result` | Action not attributable to a subject | Attributed audit log | ASI10 |
| SP13.2 | Decision Traceability | machine-readable security evidence for every authorization | No evidence why a tool/policy/identity/version authorized an action | Policy-decision records | ASI08 |
| SP13.3 | Security Event Completeness | high-impact actions are never silent | Dangerous operations without logging/alerting | Event-coverage policy + alerting config | ASI08 |

### ASP-09 · Artifact Integrity

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP14.1 | Whole-Skill Signing | `SKILL.md`, scripts, references, assets cryptographically bound together | Partial tampering undetected by content checks alone | Whole-directory signature over the skill bundle | ASI04 |
| SP14.2 | Consumer Verification | signature verified before load/execution | Signed skill loaded without verification | Verify-on-load enforcement | ASI04 |

## 7. Status model

Property-level status (from the ASPS registry and `properties.yaml`):

| Status | Meaning | Gate corpus |
|---|---|---|
| IMPLEMENTED | Covered by native deterministic rules; gate-tested | yes |
| PROVIDER_BACKED | Implemented but requires a runtime provider (OSV, YARA, semantic LLM) | yes (provider suite) |
| PARTIAL | Bounded coverage; the property is tracked but not fully gate-tested | no |
| NEW | ASPS taxonomy entry, not yet implemented in the gate corpus | no |
| PROPOSED | Taxonomy entry, not yet implemented; candidate for the lifecycle layer | no |

Fixture-level status (inside each property's `fixtures` list):

| Status | Meaning |
|---|---|
| FULL | Implemented; detected by `skil` on the positive fixture, not on the negative |
| PROVIDER_BACKED | Implemented but requires a runtime provider; excluded from the offline CI gate |
| DIFFERENT_BY_DESIGN | Deliberately not a static scanner rule; covered by the verification/contract layer |

The differential gate rejects fixture statuses `PARTIAL`, `MISSING`, and
`NOT_APPLICABLE`.

## 8. Source hierarchy and naming

The taxonomy is an integration of four source layers; names are not mixed
across layers:

```text
                    Agent Skill Security
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
     Research         Standards           Tools
        │                 │                 │
        │                 ├─ OWASP Agentic Top 10 2026 (ASI01..ASI10)
        │                 ├─ OWASP LLM Top 10
        │                 ├─ MITRE ATLAS (technique names)
        │                 ├─ MCP Security Best Practices
        │                 └─ NIST AI RMF / Generative AI Profile
        │
        ├─ Agent Skills in the Wild (Liu et al., 2026)
        ├─ Malicious Agent Skills in the Wild
        └─ Detecting Malicious Agent Skills using Attention (2026)
           Cloak and Detonate (2026)
```

Naming conventions:

- **Property IDs** are ASPS IDs `ASP-xx.yy` (domain `ASP-xx` plus a
  sequential suffix), canonical in `compat/asps/asps-registry.json`.
  Gate-corpus entries use these IDs directly in `properties.yaml`.
- **OWASP mapping** uses the canonical `ASI01`..`ASI10` and `LLM01`..`LLM10`
  IDs only.
- **ATLAS mapping** uses technique names (e.g. `AI Agent Tool Poisoning`),
  never invented IDs.
- **Detection mechanisms** (AST, taint, YARA, OSV, shell, semantic) are
  attributes of the *Control* level, never of the property itself.
- A property may map to several OWASP risks or ATLAS techniques; a property
  maps to exactly one ASPS domain.

## 9. References

- OWASP Top 10 for Agentic Applications 2026 — https://genai.owasp.org
- MITRE ATLAS — https://atlas.mitre.org
- Reference scanner corpus — patterns and rule IDs under `compat/external-scanner/`
- ASPS v1.0 (Agent Skill Security Properties Specification) — `compat/asps/ASPS-v1.0.md`
- Liu et al., *Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale* (2026) — arXiv
- *Detecting Malicious Agent Skills in the Wild using Attention* (2026) — arXiv
- *Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill Malware* (2026) — arXiv
- MCP Security Best Practices — https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- NVIDIA Signed Agent Skills (`skill.oms.sig`) — https://docs.nvidia.com/skills
- NIST AI RMF Generative AI Profile — https://www.nist.gov

# Agent Skill Security Properties Specification v1.0

Status: draft · Owner: platform-engineering · Last updated: 2026-07-31

This specification defines the security-property taxonomy that `skil` uses to
classify, detect, and verify the security of agent skill artifacts (`SKILL.md`,
scripts, references, assets, and MCP manifests). It is the conceptual layer
above `compat/external-scanner/properties.yaml`, which remains the
machine-readable, gate-enforced catalog of the implemented detection corpus.

## 1. Purpose

Provide a stable, scientifically-grounded vocabulary for agent skill security
that:

1. separates **what can go wrong** (threat) from **what must hold**
   (security property) from **how we check it** (detection mechanism) from
   **the concrete implementation** (control/rule);
2. maps every gate property to a top-level **security-property family**
   (SP01–SP14), an **OWASP Agentic Top 10 2026** risk (ASI01–ASI10), and —
   where one exists — a **MITRE ATLAS** technique;
3. tracks proposed properties that are part of the taxonomy but **not yet
   implemented** (status `PROPOSED`), so the specification remains the
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
| OWASP GenAI / LLM Top 10 | Adjacent LLM risk classes | Background for instruction & memory properties |
| MITRE ATLAS | Attacker technique catalog | Every mapped property references a technique name where applicable |
| Reference scanner corpus | Tool/vendor corpus | 64 vulnerability patterns / 16 categories; source of most original property names |
| "Agent Skills in the Wild" (Liu et al., 2026) | Empirical foundation | 14 patterns / 4 categories derived from 31,132 skills |
| MCP Security Best Practices | Protocol-level guidance | Authorization and trust-boundary properties (SP04, SP08) |
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

## 4. Top-level security-property families

| Family | Definition | Core invariant |
|---|---|---|
| **SP01 Instruction Integrity** | Untrusted content cannot override, suppress, or masquerade as higher-priority instructions. | `trusted_instructions > injected_content` |
| **SP02 Goal Integrity** | The agent's effective goal stays within the authorized goal. | `effective_goal ⊆ authorized_goal` |
| **SP03 Data Confidentiality** | Sensitive data is not read, harvested, or transmitted beyond its authorized scope. | `exfiltrated ⊥ authorized` |
| **SP04 Identity & Authorization** | Identity, credentials, and rights are scoped, non-transferable, and least-privileged. | `rights(agent) = least_privilege(task)` |
| **SP05 Tool & Capability Safety** | Tool selection, activation, and declared capabilities are bounded and explicit. | `capabilities_declared = capabilities_used` |
| **SP06 Code Execution Safety** | Untrusted or dynamically resolved input never reaches an execution sink unvalidated. | `untrusted_source ⇏ execution_sink` |
| **SP07 State & Memory Integrity** | Persistent state, memory, and configuration cannot be silently poisoned, displaced, or reset. | `state' = state ⊕ authorized_deltas` |
| **SP08 Inter-Agent Trust** | Cross-agent delegation, messaging, and output reuse preserve provenance and scope. | `C(child) ⊆ C(parent) ∩ C(delegated)` |
| **SP09 Supply Chain & Provenance** | Every artifact in the dependency and distribution chain is pinned, authenticated, and provenance-backed. | `hash(installed) = hash(reviewed)` |
| **SP10 Runtime Isolation** | Execution boundaries (OS, container, network) are not widened or escaped. | `process_scope ⊂ sandbox_boundary` |
| **SP11 Human-Agent Trust** | The agent's influence on, and disclosure toward, the user is transparent and non-manipulative. | `consent(A) ⇏ consent(B)` |
| **SP12 Availability & Resource Safety** | Resource and output bounds are finite, explicit, and reversible. | `resources ≤ budget` |
| **SP13 Auditability & Accountability** | Every security-relevant action is attributable, traceable, and evidenced. | `∀ action ∃ audit_record` |
| **SP14 Artifact Integrity** | The reviewed artifact is what is installed, executed, and attested. | `digest(artifact) = attested_digest` |

## 5. Gate corpus (implemented properties)

Source of truth: `compat/external-scanner/properties.yaml` (86 properties).
Status values: `FULL` (implemented and gate-tested), `PROVIDER_BACKED`
(requires a runtime provider, excluded from the offline CI gate),
`DIFFERENT_BY_DESIGN` (deliberately not a scanner rule; covered by the
verification layer). The differential gate rejects `PARTIAL` and `MISSING`.

| Property | Family | OWASP | ATLAS | Status |
|---|---|---|---|---|
| instruction-override | SP01 · Instruction Integrity | ASI01 | LLM Prompt Injection | FULL |
| hidden-instructions-html | SP01 · Instruction Integrity | ASI01 | LLM Prompt Injection,LLM Prompt Obfuscation | FULL |
| hidden-instructions-markdown | SP01 · Instruction Integrity | ASI01 | LLM Prompt Injection,LLM Prompt Obfuscation | FULL |
| unicode-zero-width | SP01 · Instruction Integrity | ASI01 | LLM Prompt Obfuscation | FULL |
| unicode-tag-smuggling | SP01 · Instruction Integrity | ASI01 | LLM Prompt Obfuscation | FULL |
| anti-refusal | SP01 · Instruction Integrity | ASI01 | LLM Prompt Injection | FULL |
| disclaimer-suppression | SP01 · Instruction Integrity | ASI01 | LLM Prompt Injection | FULL |
| safety-nullification | SP01 · Instruction Integrity | ASI01 | LLM Prompt Injection | FULL |
| hidden-instructions-mcp | SP01 · Instruction Integrity | ASI01 | AI Agent Tool Poisoning | FULL |
| unicode-deception-mcp | SP01 · Instruction Integrity | ASI01 | AI Agent Tool Poisoning | FULL |
| parameter-description-injection | SP01 · Instruction Integrity | ASI01 | AI Agent Tool Poisoning | FULL |
| semantic-prompt-injection | SP01 · Instruction Integrity | ASI01 | LLM Prompt Injection | FULL |
| paraphrased-attack | SP01 · Instruction Integrity | ASI01 | LLM Prompt Injection | FULL |
| physical-harm-content | SP02 · Goal Integrity | ASI01 | — | FULL |
| scope-creep | SP02 · Goal Integrity | ASI01 | — | FULL |
| exfiltration-commands | SP03 · Data Confidentiality | ASI01 | LLM Prompt Injection,Exfiltration via AI Agent Tool Invocation | FULL |
| direct-prompt-extraction | SP03 · Data Confidentiality | ASI01 | Extract LLM System Prompt | FULL |
| indirect-prompt-extraction | SP03 · Data Confidentiality | ASI01 | Extract LLM System Prompt | FULL |
| prompt-exfiltration-tool | SP03 · Data Confidentiality | ASI01 | Extract LLM System Prompt | FULL |
| external-transmission | SP03 · Data Confidentiality | ASI01 | Exfiltration via AI Agent Tool Invocation | FULL |
| env-harvesting | SP03 · Data Confidentiality | ASI03 | AI Agent Tool Credential Harvesting | FULL |
| fs-enumeration | SP03 · Data Confidentiality | ASI03 | AI Agent Tool Credential Harvesting | FULL |
| context-leakage | SP03 · Data Confidentiality | ASI01 | Exfiltration via AI Agent Tool Invocation | FULL |
| cloud-exfiltration | SP03 · Data Confidentiality | ASI02 | Exfiltration via AI Agent Tool Invocation | FULL |
| taint-credential-network | SP03 · Data Confidentiality | ASI03 | Exfiltration via AI Agent Tool Invocation | FULL |
| taint-file-network | SP03 · Data Confidentiality | ASI02 | Exfiltration via AI Agent Tool Invocation | FULL |
| nl-exfiltration | SP03 · Data Confidentiality | ASI01 | Exfiltration via AI Agent Tool Invocation | FULL |
| excessive-permissions | SP04 · Identity & Authorization | ASI03 | — | FULL |
| sudo-root-escalation | SP04 · Identity & Authorization | ASI03 | — | FULL |
| credential-file-access | SP04 · Identity & Authorization | ASI03 | AI Agent Tool Credential Harvesting | FULL |
| unrestricted-tool-access | SP05 · Tool & Capability Safety | ASI02 | AI Agent Tool Invocation | FULL |
| autonomous-decision | SP05 · Tool & Capability Safety | ASI02 | AI Agent Tool Invocation | FULL |
| broad-trigger | SP05 · Tool & Capability Safety | ASI02 | — | FULL |
| shadow-command-trigger | SP05 · Tool & Capability Safety | ASI02 | — | FULL |
| trigger-baiting | SP05 · Tool & Capability Safety | ASI02 | — | FULL |
| under-declared-capability | SP05 · Tool & Capability Safety | ASI03 | — | DIFFERENT_BY_DESIGN |
| mcp-wildcard-permission | SP05 · Tool & Capability Safety | ASI03 | AI Agent Tool Invocation | FULL |
| no-permissions-declared | SP05 · Tool & Capability Safety | ASI03 | — | FULL |
| over-declared-permission | SP05 · Tool & Capability Safety | ASI03 | — | DIFFERENT_BY_DESIGN |
| permission-pre-staging | SP05 · Tool & Capability Safety | ASI03 | — | FULL |
| description-behavior-mismatch | SP05 · Tool & Capability Safety | ASI02 | AI Agent Tool Poisoning | FULL |
| context-inappropriate-capability | SP05 · Tool & Capability Safety | ASI02 | — | FULL |
| scope-creep-permissions | SP05 · Tool & Capability Safety | ASI02 | — | FULL |
| intent-code-divergence | SP05 · Tool & Capability Safety | ASI02 | — | FULL |
| vague-triggers | SP05 · Tool & Capability Safety | ASI02 | — | DIFFERENT_BY_DESIGN |
| unvalidated-output | SP06 · Code Execution Safety | ASI05 | — | FULL |
| dynamic-python-execution | SP06 · Code Execution Safety | ASI05 | — | FULL |
| reflective-execution | SP06 · Code Execution Safety | ASI05 | — | FULL |
| taint-generic-flow | SP06 · Code Execution Safety | ASI05 | — | FULL |
| taint-variable-mediated | SP06 · Code Execution Safety | ASI05 | — | FULL |
| taint-external-execution | SP06 · Code Execution Safety | ASI05 | — | FULL |
| obfuscated-code | SP06 · Code Execution Safety | ASI05 | LLM Prompt Obfuscation | FULL |
| external-script-fetch | SP06 · Code Execution Safety | ASI05 | AI Agent Tool Invocation | FULL |
| yara-malware-signatures | SP06 · Code Execution Safety | ASI05 | — | PROVIDER_BACKED |
| persistent-context-injection | SP07 · State & Memory Integrity | ASI06 | AI Agent Context Poisoning | FULL |
| context-window-stuffing | SP07 · State & Memory Integrity | ASI06 | AI Agent Context Poisoning | FULL |
| memory-manipulation | SP07 · State & Memory Integrity | ASI06 | AI Agent Context Poisoning | FULL |
| self-modification | SP07 · State & Memory Integrity | ASI10 | Modify AI Agent Configuration | FULL |
| session-persistence | SP07 · State & Memory Integrity | ASI10 | — | FULL |
| cross-context-output | SP08 · Inter-Agent Trust | ASI07 | AI Agent Context Poisoning | FULL |
| agent-config-snooping | SP08 · Inter-Agent Trust | ASI07 | Discover AI Agent Configuration | FULL |
| mcp-config-snooping | SP08 · Inter-Agent Trust | ASI07 | Discover AI Agent Configuration | FULL |
| peer-skill-enumeration | SP08 · Inter-Agent Trust | ASI07 | Discover AI Agent Configuration | FULL |
| llm-description-behavior-mismatch | SP08 · Inter-Agent Trust | ASI02 | AI Agent Tool Poisoning | FULL |
| unpinned-dependencies | SP09 · Supply Chain & Provenance | ASI04 | — | FULL |
| vulnerable-dependency | SP09 · Supply Chain & Provenance | ASI04 | — | PROVIDER_BACKED |
| abandoned-dependency | SP09 · Supply Chain & Provenance | ASI04 | — | FULL |
| typosquatting | SP09 · Supply Chain & Provenance | ASI04 | — | FULL |
| untrusted-container-image | SP09 · Supply Chain & Provenance | ASI04 | — | FULL |
| unpinned-mcp-server | SP09 · Supply Chain & Provenance | ASI04 | AI Supply Chain Rug Pull | FULL |
| mcp-permission-manifest-diff | SP09 · Supply Chain & Provenance | ASI04 | — | DIFFERENT_BY_DESIGN |
| trigger-modification-diff | SP09 · Supply Chain & Provenance | ASI04 | — | DIFFERENT_BY_DESIGN |
| parameter-schema-modification | SP09 · Supply Chain & Provenance | ASI04 | — | DIFFERENT_BY_DESIGN |
| unpinned-skill-version | SP09 · Supply Chain & Provenance | ASI04 | — | FULL |
| docker-socket-access | SP10 · Runtime Isolation | ASI02 | AI Agent Tool Invocation | FULL |
| container-escape | SP10 · Runtime Isolation | ASI05 | AI Agent Tool Invocation | FULL |
| cloud-metadata-ssrf | SP10 · Runtime Isolation | ASI02 | AI Agent Tool Invocation | FULL |
| internal-ssrf | SP10 · Runtime Isolation | ASI02 | AI Agent Tool Invocation | FULL |
| dynamic-ssrf | SP10 · Runtime Isolation | ASI02 | AI Agent Tool Invocation | FULL |
| privileged-k8s-workload | SP10 · Runtime Isolation | ASI05 | — | FULL |
| behavior-manipulation | SP11 · Human-Agent Trust | ASI09 | Manipulate User LLM Chat History | FULL |
| undisclosed-operation | SP11 · Human-Agent Trust | ASI09 | — | FULL |
| nl-policy-violations | SP11 · Human-Agent Trust | ASI09 | — | FULL |
| narrative-deception | SP11 · Human-Agent Trust | ASI09 | — | FULL |
| unbounded-resource | SP12 · Availability & Resource Safety | ASI08 | — | FULL |
| unbounded-output | SP12 · Availability & Resource Safety | ASI08 | — | FULL |

## 6. Proposed gap properties

Status `PROPOSED`: part of the taxonomy, **not yet implemented** and **not
part of the gate corpus**. Grouped by family. Detection mechanism is the
proposed verification approach.

### SP02 Goal Integrity

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP02.3 | Goal Preservation Violation | `effective_goal ⊆ authorized_goal` | Planning derives subgoals that leave the authorized scope | Semantic contract check + plan/goal diff | ASI01 |
| SP02.4 | Control Avoidance | operative controls (monitoring, approval, sandbox, policy, shutdown) are not evaded | Agent actively routes around operational controls | Pattern + behavior-in-sandbox evidence | ASI10 |
| SP02.5 | Shutdown / Revocation Resistance | `revoke(tool) ⇒ future_use(tool) = false` | Capability continues to be used or reconstructed after revocation | Enforcement-layer capability revocation audit | ASI10 |

### SP03 Data Confidentiality

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP03.6 | Data Minimization | `required_data ⊆ available_data` | Skill reads more than its task requires | Read-scope analysis against declared task contract | ASI02 |
| SP03.7 | Purpose Limitation | `use(data, P₁) ⇒ ¬use(data, P₂)` for distinct purposes | Data obtained for one purpose reused for telemetry/training | Semantic usage-flow analysis + declared purpose | ASI01 |
| SP03.8 | Unauthorized Retention / Retention Bound | `persistence ⊆ authorized_retention` | Legitimate data persisted beyond need (distinct from memory poisoning) | Persistence-site analysis + declared retention policy | ASI06 |

### SP04 Identity & Authorization

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP04.4 | Delegated Credential Scope | `scope(delegated) ⊆ scope(required)` | OAuth/API credential with broader scope than needed | Credential-scope static analysis + contract check | ASI03 |
| SP04.5 | Credential Delegation Abuse | `credential_audience = authorized_audience` | User credential forwarded through agent to untrusted MCP/tool | Trust-boundary taint for credential objects | ASI03 |
| SP04.6 | Non-Human Identity Lifecycle | credential lifetime/scope/audience bound; non-transferable | Long-lived, unscoped machine identities (service accounts, MCP creds, cloud roles) | Identity manifest + lifecycle policy verification | ASI03 |

### SP05 Tool & Capability Safety

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP05.8 | Trigger Collision Post-Review | reviewed trigger set remains shadow-free across updates | Updated skill shadows a new built-in command | Trigger lock-diff against built-in command table | ASI02 |
| SP05.9 | Capability-Declaration Drift | `capabilities_declared ⊇ capabilities_used` continuously | Post-review code adds capability without manifest update | Continuous contract verification (skil verify) | ASI03 |

### SP08 Inter-Agent Trust

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP08.5 | Agent Identity Spoofing | `asserted_origin = authenticated_origin` | Skill claims an action/message originated from a trusted agent | Origin assertion validation in inter-agent channels | ASI07 |
| SP08.6 | Cross-Agent Trust Escalation (Confused Deputy) | delegation does not increase effective rights | Low-privilege agent reaches a high-privilege deputy | Delegation-graph rights analysis | ASI03/ASI07 |
| SP08.7 | Delegation Chain Scope Invariance | `C(child) ⊆ C(parent) ∩ C(delegated)` | Scope loss/expansion along a delegation chain | Chain-scope propagation analysis | ASI07 |
| SP08.8 | Agent Communication Integrity | agent output entering another instruction context is integrity-checked and provenance-labeled | Injected agent response promoted to trusted instruction | Cross-context taint + provenance labeling | ASI07 |
| SP08.9 | Failure Containment | a failure in one skill does not propagate unchecked | Cascading failure through trusting agents | Failure blast-radius analysis + isolation config | ASI08 |
| SP08.10 | Trust Propagation Bound | `unverified_output` remains untrusted across hops | Trust accumulated over multiple hops | Multi-hop trust-tracking (output taint) | ASI08 |

### SP09 Supply Chain & Provenance

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

### SP11 Human-Agent Trust

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP11.5 | Approval Manipulation | approval requests represent true risk | "Click approve" framing for destructive operations | Approval-prompt semantic check | ASI09 |
| SP11.6 | Consent Laundering | `consent(A) ⇏ consent(B)` | One consent interpreted as permission for broader data use | Consent-scope contract analysis | ASI09 |
| SP11.7 | Deceptive Risk Framing | permission necessity is not misrepresented | "This permission is required" when not required | Necessity justification validation | ASI09 |

### SP12 Availability & Resource Safety

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP12.4 | Action Reversibility | destructive actions follow `stage → review → commit` | Irreversible production mutation without review | Action-class policy + reversibility gate | ASI08 |

### SP13 Auditability & Accountability

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP13.1 | Action Attribution | every relevant action traceable `user→agent→skill→tool→parameters→result` | Action not attributable to a subject | Attributed audit log | ASI10 |
| SP13.2 | Decision Traceability | machine-readable security evidence for every authorization | No evidence why a tool/policy/identity/version authorized an action | Policy-decision records | ASI08 |
| SP13.3 | Security Event Completeness | high-impact actions are never silent | Dangerous operations without logging/alerting | Event-coverage policy + alerting config | ASI08 |

### SP14 Artifact Integrity

| ID | Property | Invariant | Threat | Proposed detection | OWASP |
|---|---|---|---|---|---|
| SP14.1 | Whole-Skill Signing | `SKILL.md`, scripts, references, assets cryptographically bound together | Partial tampering undetected by content checks alone | Whole-directory signature over the skill bundle | ASI04 |
| SP14.2 | Consumer Verification | signature verified before load/execution | Signed skill loaded without verification | Verify-on-load enforcement | ASI04 |

## 7. Status model

| Status | Meaning | Gate corpus |
|---|---|---|
| FULL | Implemented; detected by `skil` on the positive fixture, not on the negative | yes |
| PROVIDER_BACKED | Implemented but requires a runtime provider (OSV, YARA, semantic LLM) | yes (provider suite) |
| DIFFERENT_BY_DESIGN | Deliberately not a static scanner rule; covered by the verification/contract layer | yes |
| PARTIAL | Partially covered — **not permitted in the final gate** | no |
| MISSING | Not covered — **not permitted in the final gate** | no |
| PROPOSED | Taxonomy entry, not yet implemented; candidate for the lifecycle layer | no |
| NOT_APPLICABLE | Not applicable to agent skill artifacts | no |

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

- **Property IDs** are `SPxx` (family) plus a sequential suffix for
  sub-properties (e.g. `SP09.11`). Gate-corpus entries use their
  `properties.yaml` id (e.g. `unpinned-dependencies`).
- **OWASP mapping** uses the canonical `ASI01`..`ASI10` IDs only.
- **ATLAS mapping** uses technique names (e.g. `AI Agent Tool Poisoning`),
  never invented IDs.
- **Detection mechanisms** (AST, taint, YARA, OSV, shell, semantic) are
  attributes of the *Control* level, never of the property itself.
- A property may map to several OWASP risks or ATLAS techniques; a property
  maps to exactly one SP family.

## 9. References

- OWASP Top 10 for Agentic Applications 2026 — https://genai.owasp.org
- MITRE ATLAS — https://atlas.mitre.org
- Reference scanner corpus — patterns and rule IDs under `compat/external-scanner/`
- Liu et al., *Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale* (2026) — arXiv
- *Detecting Malicious Agent Skills in the Wild using Attention* (2026) — arXiv
- *Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill Malware* (2026) — arXiv
- MCP Security Best Practices — https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- NVIDIA Signed Agent Skills (`skill.oms.sig`) — https://docs.nvidia.com/skills
- NIST AI RMF Generative AI Profile — https://www.nist.gov

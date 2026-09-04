# Skill Trust & Agentic Supply Chain Governance Platform

SKIL evolves from a security-oriented skill scanner into a vendor-neutral **Skill Trust, Governance, Registry Admission, Evaluation, Provenance, Runtime Intelligence, and Agentic Supply Chain Governance Platform**.

Rather than only answering *"Is this skill malicious?"*, SKIL continuously calculates, explains, and enforces:

```text
Security + Quality + Necessity + Evaluation + Provenance + Integrity + Policy + Runtime Behavior + Composition Risk = Skill Trust
```

---

## 1. Unified Trust Pipeline Architecture

```text
                        Candidate Skill
                              │
                              ▼
                    Schema & Artifact Load
                              │
                              ▼
                     Static Security Analysis
                     (AST, Taint, Bytecode, YARA)
                              │
                              ▼
                     Skill Quality Analysis
                     (Completeness, Examples, Safety)
                              │
                              ▼
                   Context Efficiency Analysis
                     (Token Redundancy & Savings)
                              │
                              ▼
                    Capability Fingerprinting
                     (Domains, Actions, Tools, Perms)
                              │
                              ▼
                  Inter-Skill Duplicate Check
                     (SHA-256 & Vector Similarity)
                              │
                              ▼
                   Behavioral Skill Evaluation
                     (Task Matrix & Skill Lift %)
                              │
                              ▼
                   SKIL Skill Card Generation
                              │
                              ▼
                    Trust Score Calculator
                     (0-100 Multi-Metric Score)
                              │
                              ▼
                    Cryptographic Signing & SLSA
                     (Ed25519 DSSE Attestations)
                              │
                              ▼
                     Admission Policy Gate
               (ALLOW / WARN / REVIEW / DENY)
```

---

## 2. Trust Score & Trust Levels

SKIL computes an explainable 0–100 **Trust Score** across seven governance dimensions:

| Dimension | Default Weight | Key Input Signals |
|---|---|---|
| **Security** | 30% | AST, pattern, taint, bytecode, and threat-chain findings. |
| **Quality** | 15% | Metadata completeness, instruction clarity, usage examples, safety constraints. |
| **Evaluation / Lift** | 20% | Behavioral performance gains (`Skill Lift %`) and `pass@k` execution stability. |
| **Provenance & Signature** | 15% | Ed25519 DSSE signatures and SLSA build provenance attestations. |
| **Permission Risk** | 10% | Deductions for high-risk capabilities (shell execution, credentials, unrestricted network). |
| **Duplicate Risk** | 5% | Deductions for exact/semantic duplicates or subset capability overlaps. |
| **Runtime Stability** | 5% | Telemetry, incident signals, and runtime drift observations. |

### Governance Trust Levels

* **`VERIFIED`** (Score ≥ 90, 100% clean security, signed, build provenance verified)
* **`TRUSTED`** (Score ≥ 80)
* **`REVIEWED`** (Score ≥ 65)
* **`RESTRICTED`** (Score ≥ 45)
* **`UNTRUSTED`** (Score < 45)
* **`REVOKED`** (Explicitly revoked artifact)

---

## 3. SKIL Skill Cards

SKIL generates standardized, exportable **SKIL Skill Cards** summarizing metadata, declared capabilities, security verdict, quality rating, context efficiency, evaluation results, trust score, and cryptographic provenance.

### Example Markdown Output (`skil card ./my-skill --format markdown`):

```markdown
# SKIL Skill Card: kubernetes-deployer

**Version:** `1.2.0` | **Digest:** `sha256abc123...` | **Trust Level:** `VERIFIED`

## Trust & Admission Summary

- **Trust Score:** 92.5 / 100
- **Admission Decision:** `ACCEPT`
- **Signed Package:** `true` | **Provenance Verified:** `true`

## Security & Quality

- **Security Status:** `PASSED` (Critical: 0, High: 0, Medium: 0, Low: 0)
- **Quality Rating:** `PASS`

## Declared Capabilities

- **Domains:** kubernetes
- **Actions:** deploy, rollback
- **Tools:** kubectl, helm
- **Permissions:** cluster.read, cluster.write
```

---

## 4. Context Efficiency Analysis

Evaluate intra-skill prompt redundancy and token overhead:

```bash
skil optimize context ./my-skill
```

Output example:

```text
SKIL Context Efficiency Analysis
────────────────────────────────────────────────────────────
Total Tokens:        4,820
Instruction Tokens:  3,100
Redundant Tokens:    620
Potential Savings:   12.9%

Repeated Concepts:
  - validate cluster health before deploy (x4)
  - retry timeout policy (x3)

Recommendations:
  - Consolidate repeated prompt concepts to save up to 12.9% context capacity.
```

---

## 5. Cross-Skill Attack Path Graph

Build typed capability graphs and analyze composed multi-skill attack paths:

```bash
skil graph attack-path ./skills/secret-reader ./skills/network-uploader
```

Output example:

```text
SKIL Capability & Attack Path Graph
────────────────────────────────────────────────────────────
Total Graph Nodes: 8
Total Graph Edges: 6
Risky Paths:       true

Discovered Attack Paths:
  - [HIGH] SKIL-ATTACK-001: Composed attack path discovered: Skill 'secret-reader' reads secrets/credentials, and Skill 'network-uploader' exposes unrestricted network egress.
```

---

## 6. Version Comparison & Drift Detection

Compare two skill versions side-by-side to detect permission escalation or capability drift:

```bash
skil compare ./skills/v1.0 ./skills/v1.1
```

Output example:

```text
SKIL Version Comparison & Drift Analysis
────────────────────────────────────────────────────────────
Base Skill:   kubernetes-deployer (v1.0.0) - Score: 92.5
Target Skill: kubernetes-deployer (v1.1.0) - Score: 78.0
Score Delta:  -14.5
Perm Drift:   true
Cap Drift:    true
Decision:     REVIEW

Added Permissions: [secrets.read, cluster.write]
```

---

## 7. CLI Command Reference

| Command | Purpose |
|---|---|
| `skil trust <skill>` | Compute 0-100 Trust Score, Trust Level, and Admission Decision |
| `skil card <skill>` | Export machine-readable YAML/JSON or Markdown SKIL Skill Card |
| `skil optimize context <skill>` | Analyze prompt token redundancy & context savings |
| `skil graph capabilities <skills...>` | Render capability node & edge graph statistics |
| `skil graph attack-path <skills...>` | Discover cross-skill exfiltration attack paths |
| `skil compare <base> <target>` | Compare versions and detect permission/capability drift |


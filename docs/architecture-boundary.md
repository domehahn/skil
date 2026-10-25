# Ecosystem Architecture & Responsibility Boundaries

## Overview

In the agent governance ecosystem, **SKIL** operates as the authoritative **Security, Trust, Verification, and Assurance Plane**. 

To maintain security integrity and eliminate architectural ambiguity, responsibility is partitioned across three dedicated, non-overlapping planes:

```text
  +-------------------------------------------------------------------+
  |                          SKIL                                     |
  |     ANALYZE / VERIFY / ASSURE / ATTEST                            |
  |     - Static & semantic security analysis                        |
  |     - Capability observation & verification                      |
  |     - Risk score & explainable trust evaluation                   |
  |     - Signed Security Evidence (v1) generation                     |
  |     - skrun runtime execution receipt verification                |
  +-------------------------------------------------------------------+
                                   |
                         Signed Evidence (v1)
                                   v
  +-------------------------------------------------------------------+
  |                         SKGATE                                    |
  |     DECIDE / ADMIT / PROMOTE / REVOKE                             |
  |     - Organizational & environment policy enforcement             |
  |     - Admission decisions (ALLOW, DENY, REVIEW, REASSESS)          |
  |     - Promotion workflows (Staging -> Production)                 |
  |     - Signer & trust-anchor authorization                         |
  |     - Skill revocation & quarantine registries                     |
  +-------------------------------------------------------------------+
                                   |
                          Approved Admission
                                   v
  +-------------------------------------------------------------------+
  |                         SKRUN                                     |
  |     EXECUTE / ISOLATE / ENFORCE / RECEIPT                         |
  |     - Process spawning & container isolation                      |
  |     - Hardware / OS-level syscall containment                     |
  |     - Real-time filesystem, network & secret gating               |
  |     - Cryptographic execution receipt issuance                    |
  +-------------------------------------------------------------------+
```

---

## Canonical Authority Distribution

| Plane | Primary Responsibility | Input Artifacts | Output Evidence | Non-Goals / Excluded Authorities |
| :--- | :--- | :--- | :--- | :--- |
| **SKIL** | Security, Trust, Verification, Assurance | Skill directory, zip/tar archive, code, MCP config | `SecurityEvidenceV1`, `TrustAssessment`, `SkillCard`, DSSE Attestations | Organizational policy, deployment admission, process execution, runtime containment |
| **SKGATE** | Admission, Promotion, Organizational Policy | Signed `SecurityEvidenceV1`, organizational policy rules | Admission Decision (`ALLOW`/`DENY`), Promotion record | Code scanning, AST analysis, process execution |
| **SKRUN** | Execution, Isolation, Runtime Control | Admitted Skill, runtime policy constraints | Cryptographic Execution Receipt (`skrun.receipt.v1`) | Static security scanning, organizational policy evaluation |

---

## SKIL Boundary Rules

1. **Analysis & Attestation, Not Gatekeeping**:
   - `skil` answers *what is true about the artifact, its code, its declared capabilities, its observed behavior, and its risk profile*.
   - `skil` does NOT enforce organizational environment policies (e.g. "Only Team X can deploy to Production cluster Y").

2. **Scanner-Local Policy vs Organizational Admission Policy**:
   - `skil policy check` evaluates *scanner-local security constraints* (e.g. `critical_findings == 0`, `require_complete == true`, `capability_mismatch == false`).
   - `skgate` evaluates *organizational environment policy* (e.g. `approved_signers`, `environment == production`, `requires_human_approval`).

3. **Classification of SKIL Legacy CLI Hooks**:
   - Commands such as `skil admission` or `skil sandbox` are explicitly classified as:
     1. Scanner-internal assurance test harnesses.
     2. Compatibility helper aliases scheduled for migration to `skgate` and `skrun`.


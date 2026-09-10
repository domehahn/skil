# SKIL Threat Model

## Overview

This threat model outlines the assets, trust boundaries, threat actors, attack vectors, and security controls for **SKIL** as the authoritative Security, Trust, Verification, and Assurance Plane for AI agent skills.

---

## Assets & Trust Boundaries

```text
  [ Untrusted Skill Source / Package / Repo ]
                      |
                      | (Static AST / Code / Instructions)
                      v
      +-------------------------------+
      | SKIL Security Analyzer Plane  | <--- TRUST BOUNDARY 1 (Input Parsing)
      +-------------------------------+
                      |
                      | (Signed Evidence v1 / Attestation)
                      v
      +-------------------------------+
      | SKGATE Admission Plane        | <--- TRUST BOUNDARY 2 (Cryptographic Verification)
      +-------------------------------+
                      |
                      | (Execution Receipt v1)
                      v
      +-------------------------------+
      | SKRUN Execution Plane         | <--- TRUST BOUNDARY 3 (Runtime Isolation)
      +-------------------------------+
```

### Critical Assets
1. **Evidence Integrity & Attestations**: Cryptographic DSSE signatures and deterministic SHA256 digests binding findings to exact artifact commits.
2. **Analysis Correctness**: Zero false complete rate target on Ground Truth benchmarks; prevention of bypasses or missing findings.
3. **Scanner Host Security**: Isolation of the scanner process from malicious payload execution during static analysis or evaluation.

---

## Threat Matrix & Security Controls

| Threat Category | Attack Vector / Scenario | Potential Impact | SKIL Security Control / Mitigation |
| :--- | :--- | :--- | :--- |
| **Malicious Skill Content** | Skill contains hidden backdoors, prompt injections, obfuscated shell commands | Unsanctioned host execution, credential theft | Multi-layered static analyzers, Tree-sitter AST parsers, YARA malware signatures, local semantic analysis |
| **Parser Differential** | Exploiting differences between SKIL's parser and the host runtime interpreter | Security bypass via syntax tricks | Tree-sitter AST binding, `CallableIdentity` and `ExecutableIdentity` variable resolution |
| **Obfuscation & Encoding** | Base64, hex, XOR, or chained dynamic evaluation (`eval`, `getattr`, `vars()`) | Masking malicious sinks | Derived Security Views engine automatically decodes and proves encoded payloads |
| **Evidence Tampering** | Adversary alters scan report JSON or subject digest to pass admission | Unauthorized admission by `skgate` | DSSE Ed25519 cryptographic signing, deterministic canonical JSON serialization, explicit subject digest matching |
| **Stale Evidence** | Presenting an old scan report for a modified skill artifact | Admission of modified code | Timestamp freshness enforcement, exact subject digest validation in `skgate` interop |
| **Sandbox Escape in Eval** | Malicious skill code escapes test harness during dynamic evaluation | Host compromise | Process isolation, capability gateways, execution container containment in `skrun` |
| **False Completeness** | Scanner exits early or truncates findings, reporting partial scan as "clean" | Vulnerabilities missed | Work Accounting Ledger (`WorkLedger`), Result Commit Protocol, `--require-complete` fail-closed flag |

---

## Security Invariants

1. **Exact Subject Binding**: Evidence signed by `skil` is cryptographically bound to `sha256(artifact)`. Any modification to the artifact invalidates the signature and subject digest in `skgate`.
2. **Fail-Closed Incomplete Scans**: An incomplete scan (`AnalysisIncomplete = true`, budget exhausted, or provider timeout) under `--require-complete` must yield Exit Code 1 (`StatusFail`).
3. **No Unauthenticated Booleans**: Trust assessments rely on verified signatures, immutable digests, and deterministic scores, never on unsigned boolean flags.

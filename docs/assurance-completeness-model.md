# Assurance Completeness Model

## Overview

The **Assurance Completeness Model** in SKIL v0.7.0 transforms static and dynamic analysis from binary coverage ("scanned" vs "unscanned") to a multidimensional assurance framework. Inspired by recent industry advances in partial coverage hardening, truncated stream recovery, observer identity attestation, and ecosystem version ordering, SKIL enforces the fundamental axiom:

> **Source understood ≠ Execution target understood ≠ Analysis complete**

---

## Core Pillars

### 1. Resolution Evidence (`ResolutionEvidence`)
Identity resolution classifies how accurately execution targets (commands, subcommands, tools, dynamic variables) are bound at analysis time:

| Resolution State | Description | Example |
| :--- | :--- | :--- |
| `EXACT` | Fully and deterministically resolved identity | `cat /etc/hosts` |
| `BOUNDED_SET` | Restricted to a closed set of candidate target identities | `if X then curl else wget` |
| `PARTIAL` | Wrapper or shell builtin understood, but target remains dynamic | `eval "$DYNAMIC_CMD"` |
| `RUNTIME_UNKNOWN` | Execution target cannot be resolved prior to runtime | `$USER_INPUT_EXEC` |

### 2. Analysis Work Accounting Ledger (`WorkLedger`)
Every unit of security work discovered during skill parsing is accounted for in a strict mathematical invariant:

$$\text{scheduled} = \text{processed} + \text{transformed} + \text{skipped} + \text{unsupported} + \text{budget\_exhausted} + \text{failed}$$

Guarantees that `scheduled work = completed + explicitly incomplete + explicitly excluded`.

### 3. Result Commit Protocol (`ResultCommitProtocol`)
Evidence commitment **strictly precedes** completion finish tag validation:
- Valid security findings discovered before a stream interruption, model timeout, or LLM finish truncation are committed to the evidence graph.
- Truncation sets `AnalysisIncomplete = true` without discarding valid findings.

### 4. Observer Identity & Producer Attestation (`ObserverIdentity`)
Attests the exact identity and environment of the scanning tool/observer:
- `skil_version`: SKIL engine release.
- `binary_digest`: SHA256 digest of the running SKIL executable.
- `policy_digest`: SHA256 digest of active governance policies.
- `analyzer_set_digest`: SHA256 digest of loaded analyzers.
- `runtime_mode`: Execution environment mode (e.g. `CLI`, `CI`, `DAEMON`).
- `attestation_identity`: Cryptographic or deterministic identity string of the evidence producer.

### 5. Ecosystem-Aware Versioning (`internal/versioning`)
Provides hardened, ecosystem-aware version comparisons across:
- **SemVer**: Standard semantic versioning (`1.2.3-rc1` < `1.2.3`).
- **PEP 440**: Python package versioning (`1.0.0a1` < `1.0.0b1` < `1.0.0`).
- **Maven**: Java dependency versioning (`1.0.0-SNAPSHOT` < `1.0.0-GA`).
- **Cargo**: Rust crate versioning (`0.1.0-alpha.1` < `0.1.0`).
- **npm**: Node.js package versioning (`1.0.0-beta.2` < `1.0.0`).

### 6. Ground Truth Completeness Accuracy Benchmark
Evaluates scan outputs against ground-truth skill fixtures:
- Classifies outputs into `FULL`, `PARTIAL`, `OPAQUE`, `UNSUPPORTED`, or `BUDGET_LIMITED`.
- Calculates **False Complete Rate (FCR)**, driving false sense of security to **0%**.

---

## Command Usage

```bash
# Analyze skill resolution completeness, work accounting, and observer attestation
skil completeness ./examples/my-skill --format terminal

# Export machine-readable JSON completeness report
skil completeness ./examples/my-skill --format json
```

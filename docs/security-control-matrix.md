# Security control matrix

The matrix defines scanner-positive as a detected security concern and
scanner-negative as a legitimate counterpart that must not produce that
control. Executable regression coverage lives in
`internal/analyzer/control_matrix_test.go` and the specialized analyzer,
verification, provider, and YARA tests.

| # | Control | Native control |
| ---: | --- | --- |
| 1 | Prompt injection | `SKIL-PI-001` |
| 2 | Role/context manipulation | `SKIL-PI-002` |
| 3 | Anti-refusal | `SKIL-INTENT-REFUSAL` |
| 4 | Warning suppression | `SKIL-INTENT-WARNING` |
| 5 | Guardrail nullification | `SKIL-INTENT-GUARDRAIL` |
| 6 | Data exfiltration | `SKIL-EX-001`, `SKIL-TAINT-NETWORK` |
| 7 | Broad filesystem discovery | `SKIL-INTENT-FS-DISCOVERY` |
| 8 | Prompt leakage | `SKIL-PL-001` |
| 9 | Indirect extraction | `SKIL-PROMPT-INDIRECT-LEAK` |
| 10 | Memory poisoning | `SKIL-MP-001` |
| 11 | Context stuffing | `SKIL-MEMORY-SATURATION` |
| 12 | Excessive agency | `SKIL-AGENCY-TOOLS` |
| 13 | Approval bypass | `SKIL-AGENCY-APPROVAL` |
| 14 | Missing bounds | `SKIL-AGENCY-BOUNDS` |
| 15 | Trigger abuse | `SKIL-TRIGGER-GENERIC` |
| 16 | Trigger shadowing | `SKIL-TRIGGER-SHADOW` |
| 17 | Output execution | `SKIL-PY-001`, `SKIL-OUTPUT-EXECUTION` |
| 18 | Cross-context output | `SKIL-OUTPUT-BOUNDARY` |
| 19 | Self-modification | `SKIL-AGENT-SELF-MODIFY` |
| 20 | Persistence | `SKIL-PERSISTENCE-STARTUP` |
| 21 | Python `exec` | `SKIL-PY-001` |
| 22 | Python `eval` | `SKIL-PY-001` |
| 23 | Unsafe shell execution | `SKIL-PY-002` |
| 24 | Remote script pipeline | `SKIL-SH-001` |
| 25 | Obfuscated execution | `SKIL-OBF-001`, `SKIL-PY-001`, YARA |
| 26 | Secret-to-network taint | `SKIL-TAINT-NETWORK` |
| 27 | Input-to-execution taint | `SKIL-TAINT-EXECUTION` |
| 28 | Input-to-filesystem taint | `SKIL-TAINT-FILESYSTEM-WRITE` |
| 29 | Unpinned dependency | `SKIL-DEP-001` |
| 30 | Known vulnerability | `SKIL-DEP-VULN` with OSV |
| 31 | Typosquatting | `SKIL-DEP-002` |
| 32 | Abandoned dependency | `SKIL-DEP-ABANDONED` with trusted offline reputation |
| 33 | Container trust disabled | `SKIL-CONTAINER-TRUST` |
| 34 | YARA | `SKIL-YARA-*` |
| 35 | Unicode/Bidi/confusable | `SKIL-UNI-001`, `SKIL-UNI-002` |
| 36 | MCP wildcard | `SKIL-MCP-001` |
| 37 | Underdeclared capability | contract verification |
| 38 | Overdeclared capability | contract verification |
| 39 | MCP metadata poisoning | `SKIL-MCP-002` |
| 40 | Parameter-description injection | `SKIL-MCP-004` |
| 41 | Description/behavior mismatch | `SKIL-MCP-006` plus semantic analysis |
| 42 | MCP rug pull | `SKIL-MCP-005` and `.skil/mcp-tools.lock.json` |

Provider-backed controls remain explicit. OSV, external YARA, reputation
evidence, and semantic analysis report their real coverage and never silently
masquerade as completed.

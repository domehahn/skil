# External scanner control crosswalk

This explanatory crosswalk records the differential v2.5 reference controls
used by the conformance suite. Runtime findings remain vendor-neutral and use
only native `SKIL-*` identifiers. The mapping is about security properties,
not finding-count parity or implementation compatibility.

Coverage states:

- `FULL`: a deterministic native analyzer covers the observed property.
- `PROVIDER_BACKED`: the property is covered only when the named provider runs.
- `VERIFY_ONLY`: conformance requires a declared contract and `skil verify`.
- `PARTIAL`: a deliberately bounded implementation covers only the stated form.
- `NOT_APPLICABLE`: the reference behavior does not fit skil's assurance model.

| External ID | Reference behavior | Native equivalent | Coverage | Analyzer | Notes |
|---|---|---|---|---|---|
| AST1 | Python `exec` | `SKIL-PY-001` | FULL | Python AST | Syntax-node match; code is never imported. |
| AST2 | Python `eval` | `SKIL-PY-001` | FULL | Python AST | Shares the dynamic-execution property. |
| AST3 | Dynamic import | `SKIL-PY-001` | FULL | Python AST | Covers `__import__` and resolved aliases. |
| AST4 | `subprocess` | `SKIL-PY-002` | FULL | Python AST | Constant argv with `shell=False` is intentionally negative. |
| AST5 | `os.system` and exec family | `SKIL-PY-002` | FULL | Python AST | Includes `os.exec*` and PTY spawning. |
| AST6 | Dynamic `compile` | `SKIL-PY-001` | FULL | Python AST | Same execution boundary as `exec`. |
| AST7 | Dynamic `getattr` | `SKIL-PY-004` | FULL | Python AST | Requires a dynamic attribute selector. |
| AST8 | Dangerous execution chain | `SKIL-TAINT-EXECUTION` | FULL | Taint | Direct syntax flow plus bounded whole-artifact function summaries. |
| AST9 | Reflective execution | `SKIL-PY-REFLECT-EXEC` | FULL | Python AST | Resolves reflective execution sinks. |
| TT2 | Variable-mediated taint | `SKIL-TAINT-*` | FULL | Taint | Multi-step assignment aliases are propagated. |
| TT3 | Credential to network | `SKIL-TAINT-NETWORK` | FULL | Taint | Sensitive source to outbound sink. |
| TT4 | File to network | `SKIL-TAINT-NETWORK` | FULL | Taint | File-read source to outbound sink. |
| TT5 | External input to execution | `SKIL-TAINT-EXECUTION` | FULL | Taint | User/input source to execution sink. |
| LP3 | Capabilities observed without permission declaration | `SKIL-CAP-DECLARATION-MISSING` | FULL | Registry conformance | Advisory only; actual mismatch remains a verification concern. |
| RP1 | Mutable MCP or artifact identity | `SKIL-MCP-003`, `SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | MCP / Boundary | MCP command and args are parsed structurally. |
| E1 | External transmission | `SKIL-INTENT-EXTERNAL-TRANSFER`, `SKIL-NET-001` | FULL | Pattern / AST | Intent and executable behavior remain distinct evidence. |
| E2 | Environment-variable harvesting | `SKIL-SEC-001` | FULL | Pattern / Python AST | Concrete secret reads and credential paths. |
| EA1 | Unrestricted tool access | `SKIL-AGENCY-TOOLS`, `SKIL-MCP-001` | FULL | Pattern / MCP | Covers instructions and structured wildcard grants. |
| MP2 | Context-window stuffing | `SKIL-MEMORY-SATURATION` | FULL | Pattern | Requires displacement intent. |
| PE3 | Credential access | `SKIL-SEC-001` | FULL | Pattern / Python AST | Contextual path matching suppresses defensive statements. |
| P1 | Instruction override | `SKIL-PI-001` | FULL | Pattern | Contextual negative examples are tested. |
| SC1 | Unpinned dependency | `SKIL-DEP-001` | FULL | Dependency | Supports common manifests and lockfiles. |
| SC2 | External script fetching and execution | `SKIL-SH-001` | FULL | Shell AST | Covers download-to-shell pipelines. |
| SC3 | Obfuscated code | `SKIL-OBF-001`, `SKIL-UNI-*` | FULL | Unicode / Pattern | Conservative decoded-content and concealment checks. |
| SC4 | Known vulnerable dependency | `SKIL-DEP-VULN` | PROVIDER_BACKED | OSV | Explicit `--osv` or `--full`; default scan stays offline. |
| SC5 | Abandoned dependency | `SKIL-DEP-ABANDONED` | PROVIDER_BACKED | Offline reputation | A versioned built-in seed covers `pycrypto`; optional reviewed evidence extends it. |
| SC6 | Typosquatting | `SKIL-DEP-002` | FULL | Dependency | Ecosystem-aware canonical package names. |
| SC7 | Untrusted container image | `SKIL-CONTAINER-TRUST`, `SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | Structured AST / Boundary | Disabled trust and mutable tags are separate signals. |
| TM1 | Unsafe tool parameters | `SKIL-PY-002`, `SKIL-TAINT-EXECUTION` | FULL | Python AST / Taint | Covers dynamic argv and `shell=True`. |
| TM2 | Unsafe tool chaining | `SKIL-SH-001` | FULL | Shell AST | Pipeline is analyzed as syntax, not a comment/string. |
| TM3 | Unsafe defaults | `SKIL-TRANSPORT-INSECURE` | FULL | Pattern | Covers `verify=False`, `--insecure`, and disabled TLS/auth checks. |
| YR4 | Malware signature match | `SKIL-YARA-*` | FULL | Native malware / external YARA | The independent built-in pack is native; arbitrary external rules remain provider-backed. |

Declared-versus-observed permission mismatches are intentionally not folded
into LP3. They remain `SKIL-CAP-001` findings produced by `skil verify`, because
verification has a contract to compare while a plain scan may not.

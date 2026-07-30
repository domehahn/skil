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
| P1 | Instruction override | `SKIL-PI-001` | FULL | Pattern | Contextual negative examples are tested. |
| P4 | Covert behavioral steering | `SKIL-INTENT-BEHAVIOR-MANIPULATION` | FULL | Pattern | Covers always-prefer, never-recommend, prioritise-over-safety, gradual-steer, trust-then, appear-helpful-while patterns. |
| P5 | Physical-harm operational instruction | `SKIL-ABUSE-PHYSICAL-HARM` | FULL | Pattern | Action-anchored: poison-in-food, bleach+ammonia, self-harm, bomb/explosive construction. Safety documentation and historical discussion are negative. |
| AR1 | Anti-refusal / unconditional compliance | `SKIL-INTENT-REFUSAL` | FULL | Pattern | Covers never-refuse, always-comply, comply-mandatory, refusal-prohibited. |
| E1 | External data transmission | `SKIL-INTENT-EXTERNAL-TRANSFER`, `SKIL-NET-001` | FULL | Pattern / Code | Intent and executable behaviour remain distinct evidence. |
| E2 | Environment-variable harvesting | `SKIL-SEC-001` | FULL | Pattern / Code | Concrete secret reads and credential paths. |
| E3 | Code-level credential-directory enumeration | `SKIL-FS-DISCOVERY-CODE` | FULL | Pattern | Covers glob/os.walk/Path/iterdir/Path.home on credential-bearing directories. |
| E5 | Cloud storage exfiltration (CLI + SDK) | `SKIL-BOUNDARY-CLOUD-EXFIL`, `SKIL-BOUNDARY-CLOUD-SDK-UPLOAD` | FULL | Boundary | CLI (aws s3 cp, gsutil, azcopy) and SDK (put_object, upload_file, upload_blob) forms. |
| EA1 | Unrestricted tool access | `SKIL-AGENCY-TOOLS`, `SKIL-MCP-001` | FULL | Pattern / MCP | Covers instructions and structured wildcard grants. |
| AS1 | Agent config directory snooping | `SKIL-BOUNDARY-AGENT-STATE` | FULL | Boundary | Covers .codex, .claude, .cursor, .gemini, .continue directories and agent history/session/transcript files. |
| AS2 | MCP config snooping | `SKIL-BOUNDARY-MCP-CONFIG` | FULL | Boundary | Covers opening or enumerating mcp.json, mcp_config.json in agent config dirs, and reading MCP credentials. |
| AS3 | Peer skill enumeration | `SKIL-BOUNDARY-PEER-SKILL` | FULL | Boundary | Covers os.listdir/glob/Path.iterdir on skill directories and textual enumeration of other skills. |
| SSRF1 | Cloud metadata SSRF | `SKIL-BOUNDARY-METADATA` | FULL | Boundary | Covers 169.254.169.254, metadata.google.internal, 100.100.100.200, fd00:ec2::254. |
| SSRF2 | Internal/loopback SSRF | `SKIL-BOUNDARY-SSRF-INTERNAL` | FULL | Boundary | Covers 127.0.0.0/8, localhost, 0.0.0.0, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12. |
| SSRF3 | Dynamic-target SSRF | `SKIL-BOUNDARY-SSRF` | FULL | Boundary | Covers request primitives (requests.get, fetch, axios, curl) consuming untrusted input. |
| PE2 | sudo/root privilege escalation | `SKIL-SH-002` | FULL | Code | Covers sudo, doas, pkexec, su -, chmod u+s/+s. |
| PE3 | Credential file access | `SKIL-SEC-001` | FULL | Pattern / Code | Contextual path matching suppresses defensive statements. |
| PE4 | Docker/container socket access | `SKIL-BOUNDARY-CONTAINER` | FULL | Boundary | Covers /var/run/docker.sock, /run/containerd/containerd.sock, KUBERNETES_SERVICE_HOST. |
| PE5 | Container escape / privileged workload | `SKIL-BOUNDARY-CONTAINER-ESCAPE` | FULL | Boundary | Covers --privileged, hostNetwork/PID/IPC, SYS_ADMIN, nsenter, unshare, cgroup release_agent. |
| TM4 | Privileged Kubernetes workload | `SKIL-BOUNDARY-CONTAINER-ESCAPE` | FULL | Boundary | Covers privileged:true, hostNetwork:true, hostPID, hostIPC, allowPrivilegeEscalation, SYS_ADMIN capability, hostPath root mount. |
| LP2 | MCP wildcard permission | `SKIL-MCP-001` | FULL | MCP | Structured wildcard detection in mcp.yaml/mcp.json. |
| LP3 | Capability observed without declaration | `SKIL-CAP-DECLARATION-MISSING` | FULL | Registry conformance | Advisory only; actual mismatch remains a verification concern. |
| MP2 | Context-window stuffing | `SKIL-MEMORY-SATURATION` | FULL | Pattern | Requires displacement intent. |
| RP1 | Mutable MCP or artifact identity | `SKIL-MCP-003`, `SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | MCP / Boundary | MCP command and args are parsed structurally. |
| TP2 | Unicode homoglyph in tool/parameter identifier | `SKIL-UNI-002` | FULL | Unicode | Covers confusable hostname tokens (Latin + Cyrillic). |
| TP3 | MCP parameter-description injection | `SKIL-MCP-004` | FULL | MCP | Covers credential-collection and shell-command payloads in parameter descriptions. |
| SQP-2 | Undisclosed dangerous operation | `SKIL-INTENT-UNDISCLOSED-OPERATION` | FULL | Pattern | Covers silently/secretly/covertly + dangerous operation, and dangerous operation + without user knowledge. |
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
| SC1 | Unpinned dependency | `SKIL-DEP-001` | FULL | Dependency | Supports common manifests and lockfiles. |
| SC2 | External script fetching and execution | `SKIL-SH-001` | FULL | Shell AST | Covers download-to-shell pipelines. |
| SC3 | Obfuscated code | `SKIL-OBF-001`, `SKIL-UNI-*` | FULL | Unicode / Pattern | Conservative decoded-content and concealment checks. |
| SC4 | Known vulnerable dependency | `SKIL-DEP-VULN` | PROVIDER_BACKED | OSV | Explicit `--osv` or `--full`; default scan stays offline. |
| SC5 | Abandoned dependency | `SKIL-DEP-ABANDONED` | PROVIDER_BACKED | Offline reputation | A versioned built-in seed covers `pycrypto`; optional reviewed evidence extends it. |
| SC6 | Typosquatting | `SKIL-DEP-002` | FULL | Dependency | Ecosystem-aware canonical package names. |
| SC7 | Untrusted container image | `SKIL-CONTAINER-TRUST`, `SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | Code / Boundary | Disabled trust and mutable tags are separate signals. |
| TM1 | Unsafe tool parameters | `SKIL-PY-002`, `SKIL-TAINT-EXECUTION` | FULL | Python AST / Taint | Covers dynamic argv and `shell=True`. |
| TM2 | Unsafe tool chaining | `SKIL-SH-001` | FULL | Shell AST | Pipeline is analysed as syntax, not a comment/string. |
| TM3 | Unsafe defaults | `SKIL-TRANSPORT-INSECURE` | FULL | Pattern | Covers `verify=False`, `--insecure`, and disabled TLS/auth checks. |
| IAC-1 | Wildcard IAM policy action | `SKIL-IAC-WILDCARD-POLICY` | FULL | Boundary | Bare `"*"` action in IAM/policy statements (not service-scoped `s3:*`). |
| IAC-2 | Unrestricted CIDR range | `SKIL-IAC-OPEN-CIDR` | FULL | Boundary | `0.0.0.0/0` in network rules. |
| OH1 | Unvalidated generated-output execution | `SKIL-OUTPUT-EXECUTION` | FULL | Pattern | Covers eval/run/render of model/tool output directly. |
| OH2 | Cross-context output | `SKIL-OUTPUT-BOUNDARY` | FULL | Pattern | Covers output crossing into system prompt, trusted context, or another agent. |
| OH3 | Unbounded generated output | `SKIL-OUTPUT-LIMIT` | FULL | Pattern | Covers no/unlimited/unbounded output/token/response limit. |
| TR1 | Overly generic activation phrase | `SKIL-TRIGGER-GENERIC` | FULL | Pattern | Covers help/code/file/question as catch-all triggers. |
| TR2 | Trusted trigger shadowing | `SKIL-TRIGGER-SHADOW` | FULL | Pattern | Covers intercepting/replacing built-in commands. |
| RA1 | Rogue agent self-modification | `SKIL-AGENT-SELF-MODIFY` | FULL | Pattern | Covers rewriting own code/skill.md/configuration/policy. |
| RA2 | Unapproved startup persistence | `SKIL-PERSISTENCE-STARTUP` | FULL | Pattern / Code | Covers cron/crontab/systemd/launchctl/autorun/schtasks. |
| SDI1 | Unsafe Python deserialization | `SKIL-PY-003` | FULL | Code | Covers pickle.load(s), marshal.load(s). |
| SDI2 | JavaScript process execution | `SKIL-JS-001` | FULL | Code | Covers child_process.exec/execSync/spawn/spawnSync. |
| YR4 | Malware signature match | `SKIL-YARA-*` | FULL | Native malware / external YARA | The independent built-in pack is native; arbitrary external rules remain provider-backed. |

Declared-versus-observed permission mismatches are intentionally not folded
into LP3. They remain `SKIL-CAP-001` findings produced by `skil verify`, because
verification has a contract to compare while a plain scan may not.

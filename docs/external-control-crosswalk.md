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

The first section is auto-generated from `compat/external-scanner/properties.yaml`;
the second section contains additional conformance-suite-backed entries maintained
manually. Regenerate the first section with:

    python3 compat/external-scanner/generate_crosswalk.py --check docs/external-control-crosswalk.md

## Auto-generated (properties.yaml)

| External ID | Reference behavior | Native equivalent | Coverage | Analyzer | Notes |
|---|---|---|---|---|---|
| AR1 | Instructions demand unconditional compliance / suppress refusal | `SKIL-INTENT-REFUSAL` | FULL | Pattern | Covers never-refuse, always-comply, comply-mandatory, refusal-prohibited. |
| AS1 | Reads another agent's private configuration directory | `SKIL-BOUNDARY-AGENT-STATE` | FULL | Boundary | Covers .codex, .claude, .cursor, .gemini, .continue directories and agent history/session/transcript files. |
| AS2 | Reads or enumerates the broader agent's MCP server configuration | `SKIL-BOUNDARY-MCP-CONFIG` | FULL | MCP | Covers opening or enumerating mcp.json/mcp_config.json in agent config dirs. |
| AS3 | Enumerates or reads sibling skills' directories/manifests | `SKIL-BOUNDARY-PEER-SKILL` | FULL | Boundary | Covers os.listdir/glob/Path.iterdir on skill directories. |
| AST1 | Python dynamically executes untrusted input (exec/eval) | `SKIL-PY-001` | FULL | Code / AST | Syntax-node match; code is never imported. |
| AST9 | Reflective getattr()-resolved call to a dangerous execution sink | `SKIL-PY-REFLECT-EXEC` | FULL | Code / AST | Resolves reflective execution sinks. |
| E3 | Code recursively enumerates a home/credential-bearing directory | `SKIL-FS-DISCOVERY-CODE` | FULL | Pattern | Covers glob/os.walk/Path/iterdir/Path.home on credential-bearing directories. |
| E5 | Cloud object-storage SDK upload call (boto3/GCS/Azure SDK) | `SKIL-BOUNDARY-CLOUD-SDK-UPLOAD` | FULL | Boundary | SDK (put_object, upload_file, upload_blob) forms. |
| EA3 | NL instructions requesting scope expansion beyond stated purpose | `SKIL-INTENT-SCOPE-CREEP` | FULL | Pattern | Covers extend-scope, general-purpose, act-as-omniscient, handle-everything requests. |
| EA4 | Code-level unlimited resource pattern (float('inf'), math.inf, large number) | `SKIL-RESOURCE-UNLIMITED, SKIL-RESOURCE-TIMEOUT` | FULL | Pattern / Code | Covers code-level float('inf'), math.inf alongside NL unlimited phrasing. |
| LP2 | MCP/tool permission grant uses an unconstrained wildcard | `SKIL-MCP-001` | FULL | MCP | Structured wildcard detection in mcp.yaml/mcp.json. |
| OH1 | Model API output flows into an execution sink | `SKIL-TAINT-EXECUTION` | FULL | Taint | Model API output taint → exec/eval/subprocess sinks. |
| P1 | Fabricated instruction attempts to override higher-priority guidance | `SKIL-PI-001` | FULL | Pattern | Contextual negative examples are tested. |
| P2 | Markdown hidden comment [//]: #(...) with injection/suspicious content | `SKIL-PI-MD-HIDDEN-COMMENT, SKIL-PI-MD-SUSPICIOUS-COMMENT` | FULL | Pattern | [//]: #(...) patterns with injection or suspicious content. |
| P4 | Covert behavioral steering / dark-pattern influence on the user | `SKIL-INTENT-BEHAVIOR-MANIPULATION` | FULL | Pattern | Covers always-prefer, never-recommend, prioritise-over-safety, gradual-steer, trust-then, appear-helpful-while patterns. |
| P5 | Actionable operational instructions for causing physical harm | `SKIL-ABUSE-PHYSICAL-HARM` | FULL | Pattern | Action-anchored: poison-in-food, bleach+ammonia, self-harm, bomb/explosive construction. |
| P8 | Privileged/system prompt content flows into a file write | `SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | system_prompt → file/network/tool sink tracked via taint. |
| PE2 | Literal shell privilege-escalation command (sudo/doas/pkexec/su) | `SKIL-SH-002` | FULL | Code / AST | Covers sudo, doas, pkexec, su -, chmod u+s/+s. |
| PE3 | Reads a concrete credential-bearing file path | `SKIL-SEC-001` | FULL | Pattern | Contextual path matching suppresses defensive statements. |
| PE4 | Accesses the Docker/container control-plane socket | `SKIL-BOUNDARY-CONTAINER` | FULL | Boundary | Covers /var/run/docker.sock, /run/containerd/containerd.sock. |
| PE5 | Privileged container or host-namespace escape primitive | `SKIL-BOUNDARY-CONTAINER-ESCAPE` | FULL | Boundary | Covers --privileged, hostNetwork/PID/IPC, nsenter, unshare. |
| SQP-2 | Dangerous operation explicitly framed as hidden from the user | `SKIL-INTENT-UNDISCLOSED-OPERATION` | FULL | Pattern | Covers silently/secretly/covertly + dangerous operation, and reversed order. |
| SSRF2 | Hardcoded request to an internal/loopback/private network address | `SKIL-BOUNDARY-SSRF-INTERNAL` | FULL | Boundary | Covers 127.0.0.0/8, localhost, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12. |
| TP2 | Homoglyph substitution in an MCP tool/parameter identifier | `SKIL-UNI-002` | FULL | Pattern | Covers confusable hostname tokens (Latin + Cyrillic). |
| TP3 | MCP tool parameter description embeds an injection payload | `SKIL-MCP-004` | FULL | MCP | Covers credential-collection and shell-command payloads in parameter descriptions. |
| TR3 | Single-word trigger matches known baiting keyword | `SKIL-TRIGGER-BAITING` | FULL | Pattern / Structured | Covers anything/everything/always as triggers — structured and NL forms. |

## Manually maintained

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
| SC5 | Abandoned dependency | `SKIL-DEP-ABANDONED` | PARTIAL | Offline reputation | Built-in seed covers 27 packages (was 15) across PyPI/npm/Go; the reference scanner has ~35. No provider required. |
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
| TR3 | Keyword baiting trigger | `SKIL-TRIGGER-BAITING` | FULL | Pattern / Structured | Covers anything/everything/always as triggers — structured YAML manifest check and NL prose pattern. |
| EA3 | Scope creep | `SKIL-INTENT-SCOPE-CREEP` | FULL | Pattern / Local-semantic | Covers extend-scope, general-purpose, act-as-omniscient, handle-everything requests. Limited-scope claims remapped to real analyzer observations. |
| EA4 / OH3 | Unbounded resource / output limits | `SKIL-RESOURCE-UNLIMITED` | FULL | Pattern / Code | Covers code-level float("inf"), math.inf, 999999, 1000000 alongside NL "unlimited" phrasing. |
| OH1 (code-level) | Model output taint → execution | `SKIL-TAINT-EXECUTION` | FULL | Taint | client.responses.create(...)/chat.completions.create(...) recognized as taint source flowing to exec/eval/subprocess sinks. |
| P8 | Prompt exfiltration via tool | `SKIL-TAINT-PRIVILEGED-CONTEXT`, `SKIL-EX-001`, `SKIL-PL-001` | FULL | Taint / Pattern | system_prompt → file/network/tool sink tracked via taint, plus existing NL prompt-disclosure and exfiltration rules. |
| P2 (Markdown) | Hidden instructions in Markdown comments | `SKIL-PI-MD-HIDDEN-COMMENT`, `SKIL-PI-MD-SUSPICIOUS-COMMENT` | FULL | Pattern / Hidden-instruction | [//]: #(...) patterns with injection or suspicious content. Distinct severities (Medium/High). |
| RA1 | Rogue agent self-modification | `SKIL-AGENT-SELF-MODIFY` | FULL | Pattern | Covers rewriting own code/skill.md/configuration/policy. |
| RA2 | Unapproved startup persistence | `SKIL-PERSISTENCE-STARTUP` | FULL | Pattern / Code | Covers cron/crontab/systemd/launchctl/autorun/schtasks. |
| SDI1 | Unsafe Python deserialization | `SKIL-PY-003` | FULL | Code | Covers pickle.load(s), marshal.load(s). |
| SDI2 | JavaScript process execution | `SKIL-JS-001` | FULL | Code | Covers child_process.exec/execSync/spawn/spawnSync. |
| YR4 | Malware signature match | `SKIL-YARA-*` | FULL | Native malware / external YARA | The independent built-in pack is native; arbitrary external rules remain provider-backed. |

Declared-versus-observed permission mismatches are intentionally not folded
into LP3. They remain `SKIL-CAP-001` findings produced by `skil verify`, because
verification has a contract to compare while a plain scan may not.

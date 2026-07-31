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
| AR1 | Instructions demanding unconditional compliance / suppress refusal | `SKIL-INTENT-REFUSAL` | FULL | Pattern | Covers never-refuse, always-comply, comply-mandatory, refusal-prohibited. |
| AR2 | No warnings/don't moralize/skip the ethics instructions | `SKIL-INTENT-WARNING` | FULL | Pattern | Suppresses false positives from detect/reject X meta-discussion. |
| AR3 | You have no restrictions / DAN mode / not bound by policy | `SKIL-INTENT-GUARDRAIL` | FULL | Pattern | Also has SKIL-GUARDRAIL-I18N-001 for CJK phrasing. |
| AS1 | Reads another agent's private configuration directory | `SKIL-BOUNDARY-AGENT-STATE` | PARTIAL | Boundary | .gemini/.continue dirs not covered; does not anchor on config/settings/credentials file access. |
| AS2 | Reads/enumerates MCP server configuration | `SKIL-BOUNDARY-MCP-CONFIG` | FULL | MCP | Matches direct mcp.json/mcp_config.json access and MCP server/tool enumeration. |
| AS3 | Enumerates/reads sibling skills' directories/manifests | `SKIL-BOUNDARY-PEER-SKILL` | FULL | Boundary | Covers os.listdir/glob/Path.iterdir on skill directories. |
| AST1-9 | Python dynamically executes untrusted input (exec/eval/subprocess) | `SKIL-PY-001, SKIL-PY-002, SKIL-PY-003, SKIL-PY-004` | FULL | Code / AST | 9 dangerous-call shapes via Python AST walk. |
| AST9 | Reflective getattr()-resolved call to dangerous execution sink | `SKIL-PY-REFLECT-EXEC` | FULL | Code / AST | Resolves reflective execution sinks. |
| E1 | HTTP POST/PUT calls to external endpoints, suspicious subdomains | `SKIL-NET-001, SKIL-INTENT-EXTERNAL-TRANSFER` | FULL | Pattern | AST-anchored Python call-name resolution rather than regex. |
| E2 | Iterating env vars, reading KEY/SECRET/TOKEN/PASSWORD env vars | `SKIL-SEC-001` | FULL | Pattern | Also fires on Python AST reads (os.environ.get()). |
| E3 | Recursive walk/glob/find of home or credential directories | `SKIL-INTENT-FS-DISCOVERY, SKIL-FS-DISCOVERY-CODE` | FULL | Pattern | Covers glob/os.walk/Path/iterdir/Path.home on credential-bearing directories. |
| E4 | Instructions to send/log/export full conversation/session/memory | `SKIL-EX-001, SKIL-INTENT-EXTERNAL-TRANSFER` | PARTIAL | Pattern | Neither rule specifically targets conversation/session/memory as the exfiltrated object. |
| E5 | Cloud SDK upload calls (boto3/GCS/Azure SDK), CLI forms | `SKIL-BOUNDARY-CLOUD-EXFIL, SKIL-BOUNDARY-CLOUD-SDK-UPLOAD` | FULL | Boundary | SDK (put_object, upload_file, upload_blob) and CLI (aws s3 cp, gsutil cp) forms. |
| EA1 | Wildcard tool permissions, call any/all tools | `SKIL-AGENCY-TOOLS, SKIL-MCP-001` | FULL | MCP | Documented in external-control-crosswalk.md. |
| EA2 | Without asking confirmation/auto-approve/proceed without permission | `SKIL-AGENCY-APPROVAL` | FULL | Pattern | Requires specific high-impact verb paired with without approval. |
| EA3 | NL instructions requesting scope expansion beyond stated purpose | `SKIL-INTENT-SCOPE-CREEP` | FULL | Pattern | Covers extend-scope, general-purpose, act-as-omniscient requests. |
| EA4 | Unlimited resource access in code and NL phrasing | `SKIL-AGENCY-BOUNDS, SKIL-RESOURCE-UNLIMITED, SKIL-RESOURCE-TIMEOUT` | FULL | Pattern / Code | Covers code-level float('inf'), math.inf alongside NL unlimited phrasing. |
| LP1 | Code capability detected but not covered by declared permissions | `SKIL-CAP-DECLARATION-MISSING` | DIFFERENT_BY_DESIGN | Pattern | skil requires explicit reviewed contract (skil verify); reference scanner infers heuristically. |
| LP2 | MCP/tool permission grant uses unconstrained wildcard | `SKIL-MCP-001, SKIL-AGENCY-TOOLS` | FULL | MCP | Structured wildcard detection in mcp.yaml/mcp.json. |
| LP3 | No permissions/allowed-tools field but code capabilities exist | `SKIL-CAP-DECLARATION-MISSING` | FULL | Pattern | Documented FULL in crosswalk. |
| LP4 | Declared permission has no corresponding code capability | `SKIL-CAP-DECLARATION-MISSING` | PARTIAL | Pattern | Category-level over-declaration covered. Per-item allowlist over-declaration not covered. |
| MP1 | Remember this for all future interactions/store in memory permanently | `SKIL-MP-001` | FULL | Pattern | Matches persist-across-sessions property. |
| MP2 | Fill/stuff/flood context window to displace original instructions | `SKIL-MEMORY-SATURATION` | FULL | Pattern | Requires explicit stuff/flood/displace phrasing; no structural repeated-substring detector. |
| MP3 | Clear/wipe memory, overwrite instructions, inject false memories | `SKIL-AGENT-SELF-MODIFY, SKIL-MP-001` | PARTIAL | Pattern | Clear/reset/wipe memory and you are no longer X phrasings not covered. |
| OH1 | Model output piped into exec/eval/subprocess or code execution | `SKIL-OUTPUT-EXECUTION, SKIL-TAINT-EXECUTION` | FULL | Taint | Taint sources extended with .responses.create pattern. |
| OH2 | Output from one agent/session passed into another's system prompt | `SKIL-OUTPUT-BOUNDARY` | FULL | Boundary | Requires insert/copy tool output into system prompt/trusted context phrase. |
| OH3 | No output length/token limit, generate unlimited text | `SKIL-OUTPUT-LIMIT, SKIL-RESOURCE-UNLIMITED` | FULL | Pattern / Code | Same float('inf')/math.inf/999999 patterns as EA4 for output bounds. |
| P1 | Fabricated instruction attempts to override higher-priority guidance | `SKIL-PI-001` | FULL | Pattern | Contextual negative examples are tested. |
| P2-html | HTML comments with injection-bearing content | `SKIL-PI-HIDDEN-COMMENT` | FULL | Pattern | HTML <!--...--> comments with injection/suspicious content. |
| P2-md | Markdown hidden comments with injection/suspicious content | `SKIL-PI-MD-HIDDEN-COMMENT, SKIL-PI-MD-SUSPICIOUS-COMMENT` | FULL | Pattern | [//]: #(...) patterns with injection or suspicious content. |
| P2-tag | Unicode Tag block ASCII smuggling with RGI emoji-flag carve-out | `SKIL-UNI-003` | FULL | Pattern | Invisible U+E0000-E007F tag characters carrying hidden ASCII payload. |
| P2-zw | Zero-width chars and bidi override characters | `SKIL-UNI-001` | FULL | Pattern | Zero-width spaces, bidi overrides with emoji-ZWJ carve-out. |
| P3 | Instructions to send/transmit conversation/data to an external sink | `SKIL-EX-001, SKIL-INTENT-EXTERNAL-TRANSFER, SKIL-INTENT-UNDISCLOSED-OPERATION` | PARTIAL | Pattern | Generic conversation/context transmission with no secrecy qualifier is still not covered. |
| P4 | Covert behavioral steering / dark-pattern influence on the user | `SKIL-INTENT-BEHAVIOR-MANIPULATION` | FULL | Pattern | Covers biased recommendation steering, silent suppression, trust-then-exploit patterns. |
| P5 | Actionable operational instructions for causing physical harm | `SKIL-ABUSE-PHYSICAL-HARM` | FULL | Pattern | Action-anchored: poison-in-food, bleach+ammonia, self-harm, bomb/explosive construction. |
| P6 | Print/reveal/show system prompt instructions | `SKIL-PL-001` | FULL | Pattern | Covers direct prompt extraction with benign-heading carve-out. |
| P7 | Repeat/translate/encode/summarize instructions to leak prompt | `SKIL-PROMPT-INDIRECT-LEAK` | FULL | Pattern | Covers translate/rephrase/encode/summarize framings. |
| P8 | Save system prompt to file or send via curl/webhook | `SKIL-TAINT-PRIVILEGED-CONTEXT, SKIL-EX-001, SKIL-PL-001` | FULL | Taint | Taint test covers system_prompt flowing to file write. |
| PE1 | Wildcard or "grant me full access" permission requests | `SKIL-AGENCY-TOOLS, SKIL-MCP-001` | PARTIAL | MCP | Broader full/complete access NL phrasing outside MCP-structured blocks not matched. |
| PE2 | Literal shell privilege-escalation commands | `SKIL-SH-002` | FULL | Code / AST | Covers sudo, doas, pkexec, su -, chmod u+s/+s. |
| PE3 | Reads concrete credential-bearing file paths | `SKIL-SEC-001` | FULL | Pattern | Extended to cover K8s, Docker, GCP, Azure, browser credential paths. |
| PE4 | Accesses Docker/container control-plane socket | `SKIL-BOUNDARY-CONTAINER` | FULL | Boundary | Covers /var/run/docker.sock, /run/containerd/containerd.sock. |
| PE5 | Privileged container or host-namespace escape primitive | `SKIL-BOUNDARY-CONTAINER-ESCAPE` | FULL | Boundary | Covers --privileged, hostNetwork/PID/IPC, nsenter, unshare, cgroup release_agent. |
| RA1 | Modify own code/config/instructions/disable safety checks | `SKIL-AGENT-SELF-MODIFY` | FULL | Pattern | Matches modify/rewrite/patch your own code/instructions/policy. |
| RA2 | Crontab, bashrc/zshrc injection, systemd/launchd service, background processes | `SKIL-PERSISTENCE-STARTUP` | PARTIAL | Pattern | No equivalent for .bashrc/.zshrc append, nohup/disown, Windows registry. |
| RP1 | npx/uvx/pip install/docker pull without version pin or digest | `SKIL-MCP-003, SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | MCP | Documented FULL in crosswalk. |
| RP1-diff | Permission expansion between manifest versions | `SKIL-MCP-005` | DIFFERENT_BY_DESIGN | MCP | Lock-file diff vs caller-supplied prior manifest snapshot. |
| RP2-diff | Trigger phrase modification between versions | `SKIL-TRIGGER-LOCK-DIFF` | DIFFERENT_BY_DESIGN | Pattern / Structured | Lock-file diff vs caller-supplied prior manifest snapshot. |
| RP2-static | Add new/additional/extra permissions language in manifest | `SKIL-MANIFEST-PERMISSION-STAGING` | FULL | Pattern | Static regex over manifest text. |
| RP3-diff | Parameter type/default/description modification between versions | `SKIL-MCP-005` | PARTIAL | MCP | Lock-file diff covering tool metadata broadly, partial. |
| RP3-static | Manifest version field is wildcard or overly broad range | `SKIL-MANIFEST-UNPINNED-VERSION` | FULL | Pattern | Line-scoped regex distinguishes skill version from schema integer version. |
| SC1 | Bare package name or >= range or * in dependency files | `SKIL-DEP-001` | FULL | Pattern | Documented in external-control-crosswalk.md. |
| SC2 | curl | sh, wget | python, eval(fetch(...)) with trusted-domain allowlist | `SKIL-SH-001` | FULL | Code / AST | Documented FULL in crosswalk. |
| SC3 | exec(base64.b64decode(...)), marshal.loads, decode-then-execute chains | `SKIL-OBF-001, SKIL-UNI-001, SKIL-UNI-002` | FULL | Pattern | Documented FULL in crosswalk. |
| SC4 | Known vulnerable dependency via OSV query or static fallback | `SKIL-DEP-VULN` | PROVIDER_BACKED | Pattern | Only runs with --osv/--full; default scan is offline. |
| SC5 | Known-abandoned PyPI/npm packages | `SKIL-DEP-ABANDONED` | PARTIAL | Pattern | skil seed has 27 entries vs ~35 in reference scanner. |
| SC6 | Levenshtein edit-distance <=2 against curated popular-package lists | `SKIL-DEP-002` | FULL | Pattern | Ecosystem-aware canonical package names. |
| SC7 | --disable-content-trust / DOCKER_CONTENT_TRUST=0 / --insecure-registry | `SKIL-CONTAINER-TRUST, SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | Boundary | Documented FULL in crosswalk. |
| SDI-1 | LLM compares manifest description vs code operations | `SKIL-INTENT-DESCRIPTION` | PARTIAL | Pattern | Provider-backed. |
| SDI-2 | LLM flags capability unjustified by stated purpose | `SKIL-INTENT-CONTEXT` | PARTIAL | Pattern | Provider-backed. |
| SDI-3 | LLM compares code behavior against declared permissions | `SKIL-INTENT-SCOPE` | PARTIAL | Pattern | Provider-backed. |
| SDI-4 | LLM flags comments/docstrings contradicting code | `SKIL-INTENT-IMPLEMENTATION` | FULL | Pattern | Deterministic local-semantic pass, not LLM. |
| SQP-1 | LLM flags ambiguous/overbroad trigger phrasing | `SKIL-TRIGGER-GENERIC, SKIL-TA-001` | DIFFERENT_BY_DESIGN | Pattern / Structured | Deterministic pattern-based vs LLM; different mechanism, overlapping coverage. |
| SQP-2 | Safety-critical operations with no user-facing disclosure | `SKIL-INTENT-UNDISCLOSED-OPERATION` | PARTIAL | Pattern | Positive-signal proxy for silent/secret framing, not true absence-of-disclosure detector. |
| SQP-3 | LLM flags org-policy violations (e.g. forced language) | `` | MISSING | Pattern | Inherently an LLM-judgment property requiring a semantic provider. |
| SSD-1 | LLM detects polite/role-play/hypothetical reframings of instruction override | `SKIL-SEM-SECURITY` | PARTIAL | Pattern | Generic catch-all; not confirmed to target four SSD sub-properties with same prompt precision. |
| SSD-2 | LLM detects creative synonyms/encoded intent for known attack patterns | `SKIL-SEM-SECURITY` | PARTIAL | Pattern | Provider-backed. |
| SSD-3 | LLM detects remember everything and include in response style leaks | `SKIL-SEM-SECURITY` | PARTIAL | Pattern | Provider-backed. |
| SSD-4 | LLM detects multi-step trust-building sequences toward harm | `SKIL-SEM-COMPOSITE` | PARTIAL | Pattern | Provider-backed; conceptually close but exact prompt not confirmed. |
| SSRF1 | Cloud metadata endpoint access (169.254.169.254, metadata.google.internal) | `SKIL-BOUNDARY-METADATA` | FULL | Boundary | Requires IP/hostname co-occur with metadata/token keyword within 100 chars. |
| SSRF2 | Hardcoded request to internal/loopback/private network address | `SKIL-BOUNDARY-SSRF-INTERNAL` | FULL | Boundary | Covers 127.0.0.0/8, localhost, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12. |
| SSRF3 | F-string/template-literal URL built from interpolated variable | `SKIL-BOUNDARY-SSRF` | FULL | Boundary | Requires specific untrusted-source keyword list. |
| TM4 | Privileged: true, hostPath, hostPID, kubectl run --privileged in K8s manifest | `SKIL-BOUNDARY-CONTAINER-ESCAPE` | FULL | Boundary | K8s and Docker privilege-escape signals folded into one rule. |
| TP1 | HTML/Markdown comments, zero-width, base64 in MCP metadata fields | `SKIL-MCP-002` | PARTIAL | MCP | poisonValue regex matches literal phrases; does not check for HTML comments or base64 blobs. |
| TP2 | Homoglyph/RTL/invisible/mixed-script in tool name/triggers/parameter names | `SKIL-UNI-002, SKIL-UNI-001` | FULL | Pattern | Confusable hostname tokens, bidi overrides, invisible chars in identifiers. |
| TP3 | Instruction-override/system-prompt tokens/exfiltration in parameter description | `SKIL-MCP-004, SKIL-MCP-007` | FULL | MCP | Five sub-checks: instruction-override, exfiltration, privilege-escalation, system tokens, length. |
| TP4 | LLM compares manifest description/triggers/permissions vs code | `SKIL-MCP-006, SKIL-INTENT-DESCRIPTION` | PARTIAL | MCP | Provider-backed; default scan emits nothing for this property. |
| TR1 | Single common-word trigger or trigger <=2 chars in manifest | `SKIL-TRIGGER-GENERIC` | FULL | Pattern / Structured | Structural YAML triggers: array parsing with genericTriggerWords set-membership. |
| TR2 | Trigger collides with a built-in command name | `SKIL-TRIGGER-SHADOW` | FULL | Pattern / Structured | Set-membership check against shadowTriggerWords. |
| TR3 | Single-word trigger matches known baiting keyword | `SKIL-TRIGGER-BAITING` | FULL | Pattern / Structured | Covers anything/everything/always as triggers. |
| TT1 | Any source flowing directly into any execution/network/file-write sink | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK, SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | All 4 sink categories (network, execution, filesystem-write, log) fire unconditionally. |
| TT2 | Taint propagated through re-assignment and container literals | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK` | FULL | Taint | Multi-step assignment aliases are propagated. |
| TT3 | os.environ/os.getenv source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | Credential to network sink flow. |
| TT4 | File read source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | File read to network flow; same rule ID as TT3. |
| TT5 | External/user input flowing into execution sink | `SKIL-TAINT-EXECUTION` | FULL | Taint | requests.get/input() source to exec/eval/subprocess. |
| YR1-4 | Built-in YARA rules for malware, webshell, cryptominer, hack_tool | `SKIL-YARA-001, SKIL-YARA-002, SKIL-YARA-003, SKIL-YARA-004` | FULL | Pattern | Documented FULL in crosswalk. |

## Manually maintained

| External ID | Reference behavior | Native equivalent | Coverage | Analyzer | Notes |
|
---|---|---|---|---|---|
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

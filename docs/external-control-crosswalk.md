# External scanner control crosswalk

This explanatory crosswalk records the external reference controls used by
the conformance suite, keyed to the ASPS v1.0 taxonomy
(`compat/asps/asps-registry.json`). Runtime findings remain vendor-neutral
and use only native `SKIL-*` identifiers. The mapping is about security
properties, not finding-count parity or implementation compatibility.

Fixture-level coverage states (in `compat/external-scanner/properties.yaml`):

- `FULL`: a deterministic native analyzer covers the observed property.
- `PROVIDER_BACKED`: the property is covered only when the named provider runs.
- `DIFFERENT_BY_DESIGN`: deliberately not a static scanner rule; covered by
  the verification/contract layer.
- `VERIFY_ONLY`: conformance requires a declared contract and `skil verify`.
- `PARTIAL`: a deliberately bounded implementation covers only the stated form.
- `NOT_APPLICABLE`: the reference behavior does not fit skil's assurance model.

The first section is auto-generated from `compat/external-scanner/properties.yaml`;
the second section contains additional conformance-suite-backed entries maintained
manually. Regenerate the first section with:

    python3 compat/external-scanner/generate_crosswalk.py --check docs/external-control-crosswalk.md

## Auto-generated (properties.yaml)

| ASP Property | External ID | Reference behavior | Native equivalent | Coverage | Analyzer | Notes |
|---|---|---|---|---|---|---|
| ASP-01.01 | P1 | Fabricated instruction attempts to override higher-priority guidance | `SKIL-PI-001` | FULL | Pattern | Contextual negative examples are tested. |
| ASP-01.03 | AR1 | Instructions demanding unconditional compliance / suppress refusal | `SKIL-INTENT-REFUSAL` | FULL | Pattern | Covers never-refuse, always-comply, comply-mandatory, refusal-prohibited. |
| ASP-01.04 | AR2 | No warnings/don't moralize/skip the ethics instructions | `SKIL-INTENT-WARNING` | FULL | Pattern | Suppresses false positives from detect/reject X meta-discussion. |
| ASP-01.05 | AR3 | You have no restrictions / DAN mode / not bound by policy | `SKIL-INTENT-GUARDRAIL` | FULL | Pattern | Also has SKIL-GUARDRAIL-I18N-001 for CJK phrasing. |
| ASP-01.06 | P2 · html-comment | HTML comments with injection-bearing content | `SKIL-PI-HIDDEN-COMMENT` | FULL | Pattern | HTML <!--...--> comments with injection/suspicious content. |
| ASP-01.06 | P2 · markdown-comment | Markdown hidden comments with injection/suspicious content | `SKIL-PI-MD-HIDDEN-COMMENT, SKIL-PI-MD-SUSPICIOUS-COMMENT` | FULL | Pattern | [//]: #(...) patterns with injection or suspicious content. |
| ASP-01.06 | P2 · zero-width | Zero-width chars and bidi override characters | `SKIL-UNI-001` | FULL | Pattern | Zero-width spaces, bidi overrides with emoji-ZWJ carve-out. |
| ASP-01.06 | P2 · unicode-tag | Unicode Tag block ASCII smuggling with RGI emoji-flag carve-out | `SKIL-UNI-003` | FULL | Pattern | Invisible U+E0000-E007F tag characters carrying hidden ASCII payload. |
| ASP-01.06 | SC3 | exec(base64.b64decode(...)), marshal.loads, decode-then-execute chains | `SKIL-OBF-001, SKIL-UNI-001, SKIL-UNI-002` | FULL | Pattern | Documented FULL in crosswalk. |
| ASP-01.06 | TP2 | Homoglyph/RTL/invisible/mixed-script in tool name/triggers/parameter names | `SKIL-UNI-002, SKIL-UNI-001` | FULL | Pattern | Confusable hostname tokens, bidi overrides, invisible chars in identifiers. |
| ASP-01.07 | P4 | Covert behavioral steering / dark-pattern influence on the user | `SKIL-INTENT-BEHAVIOR-MANIPULATION` | FULL | Pattern | Covers biased recommendation steering, silent suppression, trust-then-exploit patterns. |
| ASP-01.08 | EA3 | NL instructions requesting scope expansion beyond stated purpose | `SKIL-INTENT-SCOPE-CREEP` | FULL | Pattern | Covers extend-scope, general-purpose, act-as-omniscient requests. |
| ASP-01.08 | SDI-3 (semantic) | LLM compares code behavior against declared permissions | `SKIL-INTENT-SCOPE` | FULL | Pattern | Provider-backed; verified in semantic suite. |
| ASP-02.02 | SDI-1 (semantic) | LLM compares manifest description vs code operations | `SKIL-INTENT-DESCRIPTION` | FULL | Pattern | Provider-backed; verified in semantic suite. |
| ASP-02.02 | SDI-4 (semantic) | LLM flags comments/docstrings contradicting code | `SKIL-INTENT-IMPLEMENTATION` | FULL | Pattern | Deterministic local-semantic pass, not LLM. |
| ASP-02.02 | TP4 (semantic) | LLM compares manifest description/triggers/permissions vs code | `SKIL-MCP-006, SKIL-INTENT-DESCRIPTION` | FULL | MCP | Provider-backed; SKIL-MCP-006 + SKIL-INTENT-DESCRIPTION fire when a semantic provider is configured. Verified in the semantic differential suite. |
| ASP-02.03 | SQP-1 (semantic) | LLM flags ambiguous/overbroad trigger phrasing | `SKIL-TRIGGER-GENERIC, SKIL-TA-001` | DIFFERENT_BY_DESIGN | Pattern / Structured | Deterministic pattern-based vs LLM; different mechanism, overlapping coverage. |
| ASP-02.03 | TR1 | Single common-word trigger or trigger <=2 chars in manifest | `SKIL-TRIGGER-GENERIC` | FULL | Pattern / Structured | Structural YAML triggers: array parsing with genericTriggerWords set-membership. |
| ASP-02.03 | TR3 | Single-word trigger matches known baiting keyword | `SKIL-TRIGGER-BAITING` | FULL | Pattern / Structured | Covers anything/everything/always as triggers. |
| ASP-02.04 | TR2 | Trigger collides with a built-in command name | `SKIL-TRIGGER-SHADOW` | FULL | Pattern / Structured | Set-membership check against shadowTriggerWords. |
| ASP-02.06 | SDI-1 (semantic) | LLM compares manifest description vs code operations | `SKIL-INTENT-DESCRIPTION` | FULL | Pattern | Provider-backed; verified in semantic suite. |
| ASP-02.06 | SSD-1 (semantic) | LLM detects polite/role-play/hypothetical reframings of instruction override | `SKIL-SEM-SECURITY` | FULL | Pattern | SKIL-SEM-SECURITY covers SSD-1 reframing; granularity coarser than reference. Provider-backed, verified in semantic suite. |
| ASP-02.06 | SSD-2 (semantic) | LLM detects creative synonyms/encoded intent for known attack patterns | `SKIL-SEM-SECURITY` | FULL | Pattern | SKIL-SEM-SECURITY covers paraphrased/encoded intent. Provider-backed, verified in semantic suite. |
| ASP-02.06 | SSD-3 (semantic) | LLM detects remember everything and include in response style leaks | `SKIL-SEM-SECURITY` | FULL | Pattern | SKIL-SEM-SECURITY covers remember-and-include leaks. Provider-backed, verified in semantic suite. |
| ASP-02.06 | TP4 (semantic) | LLM compares manifest description/triggers/permissions vs code | `SKIL-MCP-006, SKIL-INTENT-DESCRIPTION` | FULL | MCP | Provider-backed; SKIL-MCP-006 + SKIL-INTENT-DESCRIPTION fire when a semantic provider is configured. Verified in the semantic differential suite. |
| ASP-02.08 | LP1 | Code capability detected but not covered by declared permissions | `SKIL-CAP-DECLARATION-MISSING` | DIFFERENT_BY_DESIGN | Pattern | skil requires explicit reviewed contract (skil verify); reference scanner infers heuristically. |
| ASP-02.08 | LP3 | No permissions/allowed-tools field but code capabilities exist | `SKIL-CAP-DECLARATION-MISSING` | FULL | Pattern | Documented FULL in crosswalk. |
| ASP-02.08 | LP4 | Declared permission has no corresponding code capability | `SKIL-CAP-DECLARATION-MISSING` | DIFFERENT_BY_DESIGN | Pattern | Category-level over-declaration covered. Per-item allowlist over-declaration not covered. Declared-but-unused permissions are a verification-layer signal: skil verify enforces contract-scoped permission usage against an explicit reviewed contract, and per-item allowlist over-declaration cannot be inferred statically without reproducing false positives on legitimately unused-but-declared entries. The reference scanner's static reverse-mapping heuristic is deliberately not reproduced. |
| ASP-02.08 | SDI-1 (semantic) | LLM compares manifest description vs code operations | `SKIL-INTENT-DESCRIPTION` | FULL | Pattern | Provider-backed; verified in semantic suite. |
| ASP-02.08 | SDI-2 (semantic) | LLM flags capability unjustified by stated purpose | `SKIL-INTENT-CONTEXT` | FULL | Pattern | Provider-backed; verified in semantic suite. |
| ASP-02.08 | TP4 (semantic) | LLM compares manifest description/triggers/permissions vs code | `SKIL-MCP-006, SKIL-INTENT-DESCRIPTION` | FULL | MCP | Provider-backed; SKIL-MCP-006 + SKIL-INTENT-DESCRIPTION fire when a semantic provider is configured. Verified in the semantic differential suite. |
| ASP-03.01 | E2 | Iterating env vars, reading KEY/SECRET/TOKEN/PASSWORD env vars | `SKIL-SEC-001` | FULL | Pattern | Also fires on Python AST reads (os.environ.get()). |
| ASP-03.01 | PE3 | Reads concrete credential-bearing file paths | `SKIL-SEC-001` | FULL | Pattern | Extended to cover K8s, Docker, GCP, Azure, browser credential paths. |
| ASP-03.01 | TT1 | Any source flowing directly into any execution/network/file-write sink | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK, SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | All 4 sink categories (network, execution, filesystem-write, log) fire unconditionally. |
| ASP-03.01 | TT2 | Taint propagated through re-assignment and container literals | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK` | FULL | Taint | Multi-step assignment aliases are propagated. |
| ASP-03.01 | TT3 | os.environ/os.getenv source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | Credential to network sink flow. |
| ASP-03.01 | TT4 | File read source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | File read to network flow; same rule ID as TT3. |
| ASP-03.02 | E2 | Iterating env vars, reading KEY/SECRET/TOKEN/PASSWORD env vars | `SKIL-SEC-001` | FULL | Pattern | Also fires on Python AST reads (os.environ.get()). |
| ASP-03.02 | PE3 | Reads concrete credential-bearing file paths | `SKIL-SEC-001` | FULL | Pattern | Extended to cover K8s, Docker, GCP, Azure, browser credential paths. |
| ASP-03.03 | E1 | HTTP POST/PUT calls to external endpoints, suspicious subdomains | `SKIL-NET-001, SKIL-INTENT-EXTERNAL-TRANSFER` | FULL | Pattern | AST-anchored Python call-name resolution rather than regex. |
| ASP-03.03 | E4 | Instructions to send/log/export full conversation/session/memory | `SKIL-EX-001, SKIL-INTENT-EXTERNAL-TRANSFER` | FULL | Pattern | Neither rule specifically targets conversation/session/memory as the exfiltrated object. |
| ASP-03.03 | P3 | Instructions to send/transmit conversation/data to an external sink | `SKIL-EX-001, SKIL-INTENT-EXTERNAL-TRANSFER, SKIL-INTENT-UNDISCLOSED-OPERATION` | FULL | Pattern | SKIL-INTENT-EXTERNAL-TRANSFER covers generic conversation/data transmission without a secrecy qualifier. |
| ASP-03.03 | P8 | Save system prompt to file or send via curl/webhook | `SKIL-TAINT-PRIVILEGED-CONTEXT, SKIL-EX-001, SKIL-PL-001` | FULL | Taint | Taint test covers system_prompt flowing to file write. |
| ASP-03.04 | P6 | Print/reveal/show system prompt instructions | `SKIL-PL-001` | FULL | Pattern | Covers direct prompt extraction with benign-heading carve-out. |
| ASP-03.04 | P7 | Repeat/translate/encode/summarize instructions to leak prompt | `SKIL-PROMPT-INDIRECT-LEAK` | FULL | Pattern | Covers translate/rephrase/encode/summarize framings. |
| ASP-03.04 | P8 | Save system prompt to file or send via curl/webhook | `SKIL-TAINT-PRIVILEGED-CONTEXT, SKIL-EX-001, SKIL-PL-001` | FULL | Taint | Taint test covers system_prompt flowing to file write. |
| ASP-03.05 | E1 | HTTP POST/PUT calls to external endpoints, suspicious subdomains | `SKIL-NET-001, SKIL-INTENT-EXTERNAL-TRANSFER` | FULL | Pattern | AST-anchored Python call-name resolution rather than regex. |
| ASP-03.05 | E4 | Instructions to send/log/export full conversation/session/memory | `SKIL-EX-001, SKIL-INTENT-EXTERNAL-TRANSFER` | FULL | Pattern | Neither rule specifically targets conversation/session/memory as the exfiltrated object. |
| ASP-03.05 | P3 | Instructions to send/transmit conversation/data to an external sink | `SKIL-EX-001, SKIL-INTENT-EXTERNAL-TRANSFER, SKIL-INTENT-UNDISCLOSED-OPERATION` | FULL | Pattern | SKIL-INTENT-EXTERNAL-TRANSFER covers generic conversation/data transmission without a secrecy qualifier. |
| ASP-03.05 | P8 | Save system prompt to file or send via curl/webhook | `SKIL-TAINT-PRIVILEGED-CONTEXT, SKIL-EX-001, SKIL-PL-001` | FULL | Taint | Taint test covers system_prompt flowing to file write. |
| ASP-03.05 | TT1 | Any source flowing directly into any execution/network/file-write sink | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK, SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | All 4 sink categories (network, execution, filesystem-write, log) fire unconditionally. |
| ASP-03.05 | TT2 | Taint propagated through re-assignment and container literals | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK` | FULL | Taint | Multi-step assignment aliases are propagated. |
| ASP-03.05 | TT3 | os.environ/os.getenv source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | Credential to network sink flow. |
| ASP-03.05 | TT4 | File read source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | File read to network flow; same rule ID as TT3. |
| ASP-03.06 | E5 | Cloud SDK upload calls (boto3/GCS/Azure SDK), CLI forms | `SKIL-BOUNDARY-CLOUD-EXFIL, SKIL-BOUNDARY-CLOUD-SDK-UPLOAD` | FULL | Boundary | SDK (put_object, upload_file, upload_blob) and CLI (aws s3 cp, gsutil cp) forms. |
| ASP-03.08 | MP1 | Remember this for all future interactions/store in memory permanently | `SKIL-MP-001` | FULL | Pattern | Matches persist-across-sessions property. |
| ASP-03.08 | MP3 | Clear/wipe memory, overwrite instructions, inject false memories | `SKIL-AGENT-SELF-MODIFY, SKIL-MP-001` | FULL | Pattern | Clear/reset/wipe memory and you are no longer X phrasings not covered. |
| ASP-03.08 | RA2 | Crontab, bashrc/zshrc injection, systemd/launchd service, background processes | `SKIL-PERSISTENCE-STARTUP` | FULL | Pattern | No equivalent for .bashrc/.zshrc append, nohup/disown, Windows registry. |
| ASP-04.01 | EA1 | Wildcard tool permissions, call any/all tools | `SKIL-AGENCY-TOOLS, SKIL-MCP-001` | FULL | MCP | Documented in external-control-crosswalk.md. |
| ASP-04.01 | LP2 | MCP/tool permission grant uses unconstrained wildcard | `SKIL-MCP-001, SKIL-AGENCY-TOOLS` | FULL | MCP | Structured wildcard detection in mcp.yaml/mcp.json. |
| ASP-04.01 | PE1 | Wildcard or "grant me full access" permission requests | `SKIL-AGENCY-TOOLS, SKIL-MCP-001` | FULL | MCP | Broader full/complete access NL phrasing outside MCP-structured blocks not matched. |
| ASP-04.02 | LP1 | Code capability detected but not covered by declared permissions | `SKIL-CAP-DECLARATION-MISSING` | DIFFERENT_BY_DESIGN | Pattern | skil requires explicit reviewed contract (skil verify); reference scanner infers heuristically. |
| ASP-04.02 | LP3 | No permissions/allowed-tools field but code capabilities exist | `SKIL-CAP-DECLARATION-MISSING` | FULL | Pattern | Documented FULL in crosswalk. |
| ASP-04.02 | LP4 | Declared permission has no corresponding code capability | `SKIL-CAP-DECLARATION-MISSING` | DIFFERENT_BY_DESIGN | Pattern | Category-level over-declaration covered. Per-item allowlist over-declaration not covered. Declared-but-unused permissions are a verification-layer signal: skil verify enforces contract-scoped permission usage against an explicit reviewed contract, and per-item allowlist over-declaration cannot be inferred statically without reproducing false positives on legitimately unused-but-declared entries. The reference scanner's static reverse-mapping heuristic is deliberately not reproduced. |
| ASP-04.02 | RP2 · static-manifest | Add new/additional/extra permissions language in manifest | `SKIL-MANIFEST-PERMISSION-STAGING` | FULL | Pattern | Static regex over manifest text. |
| ASP-04.04 | EA2 | Without asking confirmation/auto-approve/proceed without permission | `SKIL-AGENCY-APPROVAL` | FULL | Pattern | Requires specific high-impact verb paired with without approval. |
| ASP-05.01 | EA1 | Wildcard tool permissions, call any/all tools | `SKIL-AGENCY-TOOLS, SKIL-MCP-001` | FULL | MCP | Documented in external-control-crosswalk.md. |
| ASP-05.01 | LP2 | MCP/tool permission grant uses unconstrained wildcard | `SKIL-MCP-001, SKIL-AGENCY-TOOLS` | FULL | MCP | Structured wildcard detection in mcp.yaml/mcp.json. |
| ASP-05.01 | PE1 | Wildcard or "grant me full access" permission requests | `SKIL-AGENCY-TOOLS, SKIL-MCP-001` | FULL | MCP | Broader full/complete access NL phrasing outside MCP-structured blocks not matched. |
| ASP-05.02 | AST1-9 · aggregate-9-shapes | Python dynamically executes untrusted input (exec/eval/subprocess) | `SKIL-PY-001, SKIL-PY-002, SKIL-PY-003, SKIL-PY-004` | FULL | Code / AST | 9 dangerous-call shapes via Python AST walk. |
| ASP-05.02 | OH1 | Model output piped into exec/eval/subprocess or code execution | `SKIL-OUTPUT-EXECUTION, SKIL-TAINT-EXECUTION` | FULL | Taint | Taint sources extended with .responses.create pattern. |
| ASP-05.02 | TP3 | Instruction-override/system-prompt tokens/exfiltration in parameter description | `SKIL-MCP-004, SKIL-MCP-007` | FULL | MCP | Five sub-checks: instruction-override, exfiltration, privilege-escalation, system tokens, length. |
| ASP-05.02 | TT1 | Any source flowing directly into any execution/network/file-write sink | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK, SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | All 4 sink categories (network, execution, filesystem-write, log) fire unconditionally. |
| ASP-05.02 | TT2 | Taint propagated through re-assignment and container literals | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK` | FULL | Taint | Multi-step assignment aliases are propagated. |
| ASP-05.02 | TT5 | External/user input flowing into execution sink | `SKIL-TAINT-EXECUTION` | FULL | Taint | requests.get/input() source to exec/eval/subprocess. |
| ASP-05.03 | SC2 | curl | sh, wget | python, eval(fetch(...)) with trusted-domain allowlist | `SKIL-SH-001` | FULL | Code / AST | Documented FULL in crosswalk. |
| ASP-05.04 | EA2 | Without asking confirmation/auto-approve/proceed without permission | `SKIL-AGENCY-APPROVAL` | FULL | Pattern | Requires specific high-impact verb paired with without approval. |
| ASP-05.07 | P3 | Instructions to send/transmit conversation/data to an external sink | `SKIL-EX-001, SKIL-INTENT-EXTERNAL-TRANSFER, SKIL-INTENT-UNDISCLOSED-OPERATION` | FULL | Pattern | SKIL-INTENT-EXTERNAL-TRANSFER covers generic conversation/data transmission without a secrecy qualifier. |
| ASP-05.07 | SQP-2 (semantic) | Safety-critical operations with no user-facing disclosure | `SKIL-INTENT-UNDISCLOSED-OPERATION` | FULL | Pattern | SKIL-INTENT-UNDISCLOSED-OPERATION fires on silent/secret framing of safety-critical operations. |
| ASP-05.08 | EA4 | Unlimited resource access in code and NL phrasing | `SKIL-AGENCY-BOUNDS, SKIL-RESOURCE-UNLIMITED, SKIL-RESOURCE-TIMEOUT` | FULL | Pattern / Code | Covers code-level float('inf'), math.inf alongside NL unlimited phrasing. |
| ASP-06.01 | AST1-9 · aggregate-9-shapes | Python dynamically executes untrusted input (exec/eval/subprocess) | `SKIL-PY-001, SKIL-PY-002, SKIL-PY-003, SKIL-PY-004` | FULL | Code / AST | 9 dangerous-call shapes via Python AST walk. |
| ASP-06.01 | AST9 | Reflective getattr()-resolved call to dangerous execution sink | `SKIL-PY-REFLECT-EXEC` | FULL | Code / AST | Resolves reflective execution sinks. |
| ASP-06.02 | AST1-9 · aggregate-9-shapes | Python dynamically executes untrusted input (exec/eval/subprocess) | `SKIL-PY-001, SKIL-PY-002, SKIL-PY-003, SKIL-PY-004` | FULL | Code / AST | 9 dangerous-call shapes via Python AST walk. |
| ASP-06.02 | OH1 | Model output piped into exec/eval/subprocess or code execution | `SKIL-OUTPUT-EXECUTION, SKIL-TAINT-EXECUTION` | FULL | Taint | Taint sources extended with .responses.create pattern. |
| ASP-06.02 | TT1 | Any source flowing directly into any execution/network/file-write sink | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK, SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | All 4 sink categories (network, execution, filesystem-write, log) fire unconditionally. |
| ASP-06.02 | TT2 | Taint propagated through re-assignment and container literals | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK` | FULL | Taint | Multi-step assignment aliases are propagated. |
| ASP-06.02 | TT5 | External/user input flowing into execution sink | `SKIL-TAINT-EXECUTION` | FULL | Taint | requests.get/input() source to exec/eval/subprocess. |
| ASP-06.03 | PE2 | Literal shell privilege-escalation commands | `SKIL-SH-002` | FULL | Code / AST | Covers sudo, doas, pkexec, su -, chmod u+s/+s. |
| ASP-06.03 | SC2 | curl | sh, wget | python, eval(fetch(...)) with trusted-domain allowlist | `SKIL-SH-001` | FULL | Code / AST | Documented FULL in crosswalk. |
| ASP-06.04 | AST1-9 · aggregate-9-shapes | Python dynamically executes untrusted input (exec/eval/subprocess) | `SKIL-PY-001, SKIL-PY-002, SKIL-PY-003, SKIL-PY-004` | FULL | Code / AST | 9 dangerous-call shapes via Python AST walk. |
| ASP-06.05 | OH1 | Model output piped into exec/eval/subprocess or code execution | `SKIL-OUTPUT-EXECUTION, SKIL-TAINT-EXECUTION` | FULL | Taint | Taint sources extended with .responses.create pattern. |
| ASP-06.05 | TT1 | Any source flowing directly into any execution/network/file-write sink | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK, SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | All 4 sink categories (network, execution, filesystem-write, log) fire unconditionally. |
| ASP-06.05 | TT2 | Taint propagated through re-assignment and container literals | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK` | FULL | Taint | Multi-step assignment aliases are propagated. |
| ASP-06.05 | TT5 | External/user input flowing into execution sink | `SKIL-TAINT-EXECUTION` | FULL | Taint | requests.get/input() source to exec/eval/subprocess. |
| ASP-06.06 | OH2 | Output from one agent/session passed into another's system prompt | `SKIL-OUTPUT-BOUNDARY` | FULL | Boundary | Requires insert/copy tool output into system prompt/trusted context phrase. |
| ASP-06.07 | OH1 | Model output piped into exec/eval/subprocess or code execution | `SKIL-OUTPUT-EXECUTION, SKIL-TAINT-EXECUTION` | FULL | Taint | Taint sources extended with .responses.create pattern. |
| ASP-06.07 | TT1 | Any source flowing directly into any execution/network/file-write sink | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK, SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | All 4 sink categories (network, execution, filesystem-write, log) fire unconditionally. |
| ASP-06.07 | TT2 | Taint propagated through re-assignment and container literals | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK` | FULL | Taint | Multi-step assignment aliases are propagated. |
| ASP-06.07 | TT3 | os.environ/os.getenv source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | Credential to network sink flow. |
| ASP-06.07 | TT4 | File read source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | File read to network flow; same rule ID as TT3. |
| ASP-06.07 | TT5 | External/user input flowing into execution sink | `SKIL-TAINT-EXECUTION` | FULL | Taint | requests.get/input() source to exec/eval/subprocess. |
| ASP-06.08 | SC3 | exec(base64.b64decode(...)), marshal.loads, decode-then-execute chains | `SKIL-OBF-001, SKIL-UNI-001, SKIL-UNI-002` | FULL | Pattern | Documented FULL in crosswalk. |
| ASP-06.08 | YR1-4 · aggregate-4-rules (provider) | Built-in YARA rules for malware, webshell, cryptominer, hack_tool | `SKIL-YARA-001, SKIL-YARA-002, SKIL-YARA-003, SKIL-YARA-004` | PROVIDER_BACKED | Pattern | Documented FULL in crosswalk. Requires the system yara runtime with the embedded default rule set; excluded from the offline CI static gate, verified in the provider suite. |
| ASP-07.01 | MP1 | Remember this for all future interactions/store in memory permanently | `SKIL-MP-001` | FULL | Pattern | Matches persist-across-sessions property. |
| ASP-07.01 | MP3 | Clear/wipe memory, overwrite instructions, inject false memories | `SKIL-AGENT-SELF-MODIFY, SKIL-MP-001` | FULL | Pattern | Clear/reset/wipe memory and you are no longer X phrasings not covered. |
| ASP-07.02 | MP2 | Fill/stuff/flood context window to displace original instructions | `SKIL-MEMORY-SATURATION` | FULL | Pattern | Requires explicit stuff/flood/displace phrasing; no structural repeated-substring detector. |
| ASP-07.03 | MP1 | Remember this for all future interactions/store in memory permanently | `SKIL-MP-001` | FULL | Pattern | Matches persist-across-sessions property. |
| ASP-07.03 | MP3 | Clear/wipe memory, overwrite instructions, inject false memories | `SKIL-AGENT-SELF-MODIFY, SKIL-MP-001` | FULL | Pattern | Clear/reset/wipe memory and you are no longer X phrasings not covered. |
| ASP-07.03 | RA1 | Modify own code/config/instructions/disable safety checks | `SKIL-AGENT-SELF-MODIFY` | FULL | Pattern | Matches modify/rewrite/patch your own code/instructions/policy. |
| ASP-07.04 | MP3 | Clear/wipe memory, overwrite instructions, inject false memories | `SKIL-AGENT-SELF-MODIFY, SKIL-MP-001` | FULL | Pattern | Clear/reset/wipe memory and you are no longer X phrasings not covered. |
| ASP-07.04 | RA1 | Modify own code/config/instructions/disable safety checks | `SKIL-AGENT-SELF-MODIFY` | FULL | Pattern | Matches modify/rewrite/patch your own code/instructions/policy. |
| ASP-07.05 | RA2 | Crontab, bashrc/zshrc injection, systemd/launchd service, background processes | `SKIL-PERSISTENCE-STARTUP` | FULL | Pattern | No equivalent for .bashrc/.zshrc append, nohup/disown, Windows registry. |
| ASP-08.05 | OH2 | Output from one agent/session passed into another's system prompt | `SKIL-OUTPUT-BOUNDARY` | FULL | Boundary | Requires insert/copy tool output into system prompt/trusted context phrase. |
| ASP-08.06 | OH2 | Output from one agent/session passed into another's system prompt | `SKIL-OUTPUT-BOUNDARY` | FULL | Boundary | Requires insert/copy tool output into system prompt/trusted context phrase. |
| ASP-09.06 | RP1 · version-diff | Permission expansion between manifest versions | `SKIL-MCP-005` | DIFFERENT_BY_DESIGN | MCP | Lock-file diff vs caller-supplied prior manifest snapshot. |
| ASP-09.06 | RP2 · version-diff | Trigger phrase modification between versions | `SKIL-TRIGGER-LOCK-DIFF` | DIFFERENT_BY_DESIGN | Pattern / Structured | Lock-file diff vs caller-supplied prior manifest snapshot. |
| ASP-09.06 | RP3 · version-diff | Parameter type/default/description modification between versions | `SKIL-MCP-005` | DIFFERENT_BY_DESIGN | MCP | Requires comparing two manifest snapshots; skil lock-diff (SKIL-MCP-005) covers tool metadata, caller supplies prior snapshot. By design. |
| ASP-09.07 | RP1 | npx/uvx/pip install/docker pull without version pin or digest | `SKIL-MCP-003, SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | MCP | Documented FULL in crosswalk. |
| ASP-09.07 | RP1 · version-diff | Permission expansion between manifest versions | `SKIL-MCP-005` | DIFFERENT_BY_DESIGN | MCP | Lock-file diff vs caller-supplied prior manifest snapshot. |
| ASP-09.07 | RP3 · version-diff | Parameter type/default/description modification between versions | `SKIL-MCP-005` | DIFFERENT_BY_DESIGN | MCP | Requires comparing two manifest snapshots; skil lock-diff (SKIL-MCP-005) covers tool metadata, caller supplies prior snapshot. By design. |
| ASP-09.08 | RP1 | npx/uvx/pip install/docker pull without version pin or digest | `SKIL-MCP-003, SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | MCP | Documented FULL in crosswalk. |
| ASP-09.08 | SC7 | --disable-content-trust / DOCKER_CONTENT_TRUST=0 / --insecure-registry | `SKIL-CONTAINER-TRUST, SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | Boundary | Documented FULL in crosswalk. |
| ASP-10.01 | EA1 | Wildcard tool permissions, call any/all tools | `SKIL-AGENCY-TOOLS, SKIL-MCP-001` | FULL | MCP | Documented in external-control-crosswalk.md. |
| ASP-10.01 | LP2 | MCP/tool permission grant uses unconstrained wildcard | `SKIL-MCP-001, SKIL-AGENCY-TOOLS` | FULL | MCP | Structured wildcard detection in mcp.yaml/mcp.json. |
| ASP-10.01 | PE1 | Wildcard or "grant me full access" permission requests | `SKIL-AGENCY-TOOLS, SKIL-MCP-001` | FULL | MCP | Broader full/complete access NL phrasing outside MCP-structured blocks not matched. |
| ASP-10.02 | P2 · zero-width | Zero-width chars and bidi override characters | `SKIL-UNI-001` | FULL | Pattern | Zero-width spaces, bidi overrides with emoji-ZWJ carve-out. |
| ASP-10.02 | SC3 | exec(base64.b64decode(...)), marshal.loads, decode-then-execute chains | `SKIL-OBF-001, SKIL-UNI-001, SKIL-UNI-002` | FULL | Pattern | Documented FULL in crosswalk. |
| ASP-10.02 | TP1 | HTML/Markdown comments, zero-width, base64 in MCP metadata fields | `SKIL-MCP-002` | FULL | MCP | MCP metadata fields embedding injection instructions; covered by SKIL-MCP-002 poisonValue on description/default fields. |
| ASP-10.02 | TP2 | Homoglyph/RTL/invisible/mixed-script in tool name/triggers/parameter names | `SKIL-UNI-002, SKIL-UNI-001` | FULL | Pattern | Confusable hostname tokens, bidi overrides, invisible chars in identifiers. |
| ASP-10.03 | TP3 | Instruction-override/system-prompt tokens/exfiltration in parameter description | `SKIL-MCP-004, SKIL-MCP-007` | FULL | MCP | Five sub-checks: instruction-override, exfiltration, privilege-escalation, system tokens, length. |
| ASP-10.04 | RP1 | npx/uvx/pip install/docker pull without version pin or digest | `SKIL-MCP-003, SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | MCP | Documented FULL in crosswalk. |
| ASP-10.04 | RP1 · version-diff | Permission expansion between manifest versions | `SKIL-MCP-005` | DIFFERENT_BY_DESIGN | MCP | Lock-file diff vs caller-supplied prior manifest snapshot. |
| ASP-10.04 | RP3 · version-diff | Parameter type/default/description modification between versions | `SKIL-MCP-005` | DIFFERENT_BY_DESIGN | MCP | Requires comparing two manifest snapshots; skil lock-diff (SKIL-MCP-005) covers tool metadata, caller supplies prior snapshot. By design. |
| ASP-10.05 | SDI-1 (semantic) | LLM compares manifest description vs code operations | `SKIL-INTENT-DESCRIPTION` | FULL | Pattern | Provider-backed; verified in semantic suite. |
| ASP-10.05 | TP4 (semantic) | LLM compares manifest description/triggers/permissions vs code | `SKIL-MCP-006, SKIL-INTENT-DESCRIPTION` | FULL | MCP | Provider-backed; SKIL-MCP-006 + SKIL-INTENT-DESCRIPTION fire when a semantic provider is configured. Verified in the semantic differential suite. |
| ASP-11.01 | E1 | HTTP POST/PUT calls to external endpoints, suspicious subdomains | `SKIL-NET-001, SKIL-INTENT-EXTERNAL-TRANSFER` | FULL | Pattern | AST-anchored Python call-name resolution rather than regex. |
| ASP-11.01 | TT1 | Any source flowing directly into any execution/network/file-write sink | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK, SKIL-TAINT-PRIVILEGED-CONTEXT` | FULL | Taint | All 4 sink categories (network, execution, filesystem-write, log) fire unconditionally. |
| ASP-11.01 | TT2 | Taint propagated through re-assignment and container literals | `SKIL-TAINT-EXECUTION, SKIL-TAINT-NETWORK` | FULL | Taint | Multi-step assignment aliases are propagated. |
| ASP-11.01 | TT3 | os.environ/os.getenv source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | Credential to network sink flow. |
| ASP-11.01 | TT4 | File read source flowing to network sink | `SKIL-TAINT-NETWORK` | FULL | Taint | File read to network flow; same rule ID as TT3. |
| ASP-11.02 | SSRF1 | Cloud metadata endpoint access (169.254.169.254, metadata.google.internal) | `SKIL-BOUNDARY-METADATA` | FULL | Boundary | Requires IP/hostname co-occur with metadata/token keyword within 100 chars. |
| ASP-11.03 | SSRF2 | Hardcoded request to internal/loopback/private network address | `SKIL-BOUNDARY-SSRF-INTERNAL` | FULL | Boundary | Covers 127.0.0.0/8, localhost, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12. |
| ASP-11.04 | SSRF3 | F-string/template-literal URL built from interpolated variable | `SKIL-BOUNDARY-SSRF` | FULL | Boundary | Requires specific untrusted-source keyword list. |
| ASP-11.05 | AS1 | Reads another agent's private configuration directory | `SKIL-BOUNDARY-AGENT-STATE` | FULL | Boundary | .gemini/.continue dirs not covered; does not anchor on config/settings/credentials file access. |
| ASP-11.05 | AS2 | Reads/enumerates MCP server configuration | `SKIL-BOUNDARY-MCP-CONFIG` | FULL | MCP | Matches direct mcp.json/mcp_config.json access and MCP server/tool enumeration. |
| ASP-11.05 | E3 | Recursive walk/glob/find of home or credential directories | `SKIL-INTENT-FS-DISCOVERY, SKIL-FS-DISCOVERY-CODE` | FULL | Pattern | Covers glob/os.walk/Path/iterdir/Path.home on credential-bearing directories. |
| ASP-11.06 | AS3 | Enumerates/reads sibling skills' directories/manifests | `SKIL-BOUNDARY-PEER-SKILL` | FULL | Boundary | Covers os.listdir/glob/Path.iterdir on skill directories. |
| ASP-11.07 | PE4 | Accesses Docker/container control-plane socket | `SKIL-BOUNDARY-CONTAINER` | FULL | Boundary | Covers /var/run/docker.sock, /run/containerd/containerd.sock. |
| ASP-11.08 | PE2 | Literal shell privilege-escalation commands | `SKIL-SH-002` | FULL | Code / AST | Covers sudo, doas, pkexec, su -, chmod u+s/+s. |
| ASP-11.08 | PE5 | Privileged container or host-namespace escape primitive | `SKIL-BOUNDARY-CONTAINER-ESCAPE` | FULL | Boundary | Covers --privileged, hostNetwork/PID/IPC, nsenter, unshare, cgroup release_agent. |
| ASP-11.08 | TM4 | Privileged: true, hostPath, hostPID, kubectl run --privileged in K8s manifest | `SKIL-BOUNDARY-CONTAINER-ESCAPE` | FULL | Boundary | K8s and Docker privilege-escape signals folded into one rule. |
| ASP-12.01 | EA4 | Unlimited resource access in code and NL phrasing | `SKIL-AGENCY-BOUNDS, SKIL-RESOURCE-UNLIMITED, SKIL-RESOURCE-TIMEOUT` | FULL | Pattern / Code | Covers code-level float('inf'), math.inf alongside NL unlimited phrasing. |
| ASP-12.02 | OH3 | No output length/token limit, generate unlimited text | `SKIL-OUTPUT-LIMIT, SKIL-RESOURCE-UNLIMITED` | FULL | Pattern / Code | Same float('inf')/math.inf/999999 patterns as EA4 for output bounds. |
| ASP-12.03 | EA4 | Unlimited resource access in code and NL phrasing | `SKIL-AGENCY-BOUNDS, SKIL-RESOURCE-UNLIMITED, SKIL-RESOURCE-TIMEOUT` | FULL | Pattern / Code | Covers code-level float('inf'), math.inf alongside NL unlimited phrasing. |
| ASP-12.07 | EA4 | Unlimited resource access in code and NL phrasing | `SKIL-AGENCY-BOUNDS, SKIL-RESOURCE-UNLIMITED, SKIL-RESOURCE-TIMEOUT` | FULL | Pattern / Code | Covers code-level float('inf'), math.inf alongside NL unlimited phrasing. |
| ASP-13.01 | P3 | Instructions to send/transmit conversation/data to an external sink | `SKIL-EX-001, SKIL-INTENT-EXTERNAL-TRANSFER, SKIL-INTENT-UNDISCLOSED-OPERATION` | FULL | Pattern | SKIL-INTENT-EXTERNAL-TRANSFER covers generic conversation/data transmission without a secrecy qualifier. |
| ASP-13.01 | SQP-2 (semantic) | Safety-critical operations with no user-facing disclosure | `SKIL-INTENT-UNDISCLOSED-OPERATION` | FULL | Pattern | SKIL-INTENT-UNDISCLOSED-OPERATION fires on silent/secret framing of safety-critical operations. |
| ASP-13.02 | EA2 | Without asking confirmation/auto-approve/proceed without permission | `SKIL-AGENCY-APPROVAL` | FULL | Pattern | Requires specific high-impact verb paired with without approval. |
| ASP-13.03 | P4 | Covert behavioral steering / dark-pattern influence on the user | `SKIL-INTENT-BEHAVIOR-MANIPULATION` | FULL | Pattern | Covers biased recommendation steering, silent suppression, trust-then-exploit patterns. |
| ASP-13.03 | SQP-3 (semantic) | LLM flags org-policy violations (e.g. forced language) | `SKIL-SEM-POLICY` | FULL | Pattern | Provider-backed semantic control for organization-policy violations (e.g. forced language). |
| ASP-13.03 | SSD-4 (semantic) | LLM detects multi-step trust-building sequences toward harm | `SKIL-SEM-COMPOSITE` | FULL | Pattern | SKIL-SEM-COMPOSITE covers multi-step trust-building. Provider-backed, verified in semantic suite. |
| ASP-13.04 | EA2 | Without asking confirmation/auto-approve/proceed without permission | `SKIL-AGENCY-APPROVAL` | FULL | Pattern | Requires specific high-impact verb paired with without approval. |
| ASP-13.05 | P5 | Actionable operational instructions for causing physical harm | `SKIL-ABUSE-PHYSICAL-HARM` | FULL | Pattern | Action-anchored: poison-in-food, bleach+ammonia, self-harm, bomb/explosive construction. |
| ASP-15.01 | RP3 · static-manifest | Manifest version field is wildcard or overly broad range | `SKIL-MANIFEST-UNPINNED-VERSION` | FULL | Pattern | Line-scoped regex distinguishes skill version from schema integer version. |
| ASP-15.01 | SC1 | Bare package name or >= range or * in dependency files | `SKIL-DEP-001` | FULL | Pattern | Documented in external-control-crosswalk.md. |
| ASP-15.02 | SC4 (provider) | Known vulnerable dependency via OSV query or static fallback | `SKIL-DEP-VULN` | PROVIDER_BACKED | Pattern | Only runs with --osv/--full; default scan is offline. Runs only with --osv (live OSV query with offline static fallback); excluded from the offline CI static gate, verified in the provider suite. |
| ASP-15.03 | SC3 | exec(base64.b64decode(...)), marshal.loads, decode-then-execute chains | `SKIL-OBF-001, SKIL-UNI-001, SKIL-UNI-002` | FULL | Pattern | Documented FULL in crosswalk. |
| ASP-15.03 | SC6 | Levenshtein edit-distance <=2 against curated popular-package lists | `SKIL-DEP-002` | FULL | Pattern | Ecosystem-aware canonical package names. |
| ASP-15.03 | TP2 | Homoglyph/RTL/invisible/mixed-script in tool name/triggers/parameter names | `SKIL-UNI-002, SKIL-UNI-001` | FULL | Pattern | Confusable hostname tokens, bidi overrides, invisible chars in identifiers. |
| ASP-15.04 | SC5 | Known-abandoned PyPI/npm packages | `SKIL-DEP-ABANDONED` | FULL | Pattern | skil seed has 27 entries vs ~35 in reference scanner. |
| ASP-15.07 | SC2 | curl | sh, wget | python, eval(fetch(...)) with trusted-domain allowlist | `SKIL-SH-001` | FULL | Code / AST | Documented FULL in crosswalk. |
| ASP-15.08 | RP1 | npx/uvx/pip install/docker pull without version pin or digest | `SKIL-MCP-003, SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | MCP | Documented FULL in crosswalk. |
| ASP-15.08 | SC7 | --disable-content-trust / DOCKER_CONTENT_TRUST=0 / --insecure-registry | `SKIL-CONTAINER-TRUST, SKIL-BOUNDARY-MUTABLE-IMAGE` | FULL | Boundary | Documented FULL in crosswalk. |
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

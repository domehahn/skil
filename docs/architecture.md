# Architecture

The public `pkg/skil` package contains stable models and narrow extension
interfaces. `internal/artifact` creates a canonical, immutable input view;
`internal/analyzer` runs independent read-only analyzers; `verification`
compares observed behavior with `SkillContract`; `eval` is the only execution
boundary; `policy` consumes results but never scans; `evidence` binds results to
digests; and `report` only serializes.

Containment reuses this path:
`eval spec -> isolated adapter -> host gateway -> contract plus eval target
authorization -> trusted tool -> host-owned trace -> metrics -> policy/evidence`.
There is no second execution or policy framework. The additive
`AssuranceRuntime` interface exposes enforcement/isolation coverage; older
runtimes remain source-compatible but cannot claim containment.

```text
source -> race-resistant ingestor -> canonical artifact + digest
                                     ├-> derived security views -> existing analyzers
                                     ├-> analyzers -> findings + coverage + inspection ledger
                                     ├-> local/transitive graph -> assurance closure + closure digest
contract ----------------------------┴-> verification
eval spec -> isolated adapter -> tool request -> host gateway -> enforcer -> host tool
                                  └-> bounded result -> adapter -> final output
trusted gateway records -------------------------------> trace + metrics
scan/closure/eval evidence -> attestation -> policy decision
```

Core, scanner, semantic provider, policy engine, and eval harness have no
backwards dependencies. Providers cannot acquire tools through their interface.
The CLI composes modules and maps errors to stable exit codes.

Optional analysis is composed through one shared CLI configuration used by
scan, verification, attestation, policy, and installation. Tree-sitter AST,
local intent correlation, and the native malware signature pack remain local.
OSV, arbitrary-source YARA, and model-semantic adapters are registered only by
explicit flags, so their coverage cannot be confused with the default offline
scan.

`scan-all` is a discovery/composition layer, not a separate scanner: every
concrete skill receives its own artifact digest and complete analyzer ledger.
The scanner MCP service exposes the same path through a configured filesystem
root. Stdio is process-confined; HTTP is loopback-only and requires a
constant-time checked bearer token.

Assurance levels describe completed work, not safety: `UNVERIFIED`,
`VALIDATED`, `STATIC_ANALYZED`, `SEMANTIC_ANALYZED`,
`BEHAVIORALLY_EVALUATED`, `ATTESTED`, and `POLICY_APPROVED`.

## Assurance closure lifecycle

`internal/assurance` is the single normalization and trust-aggregation layer.
It canonicalizes nodes, edges, limitations, and finding references before
hashing, so traversal order and cycles cannot change identity. Every required
node carries a kind, content digest, analysis status, verification status, and
verdict. Aggregation is fail closed: an unsafe required descendant makes the
closure `UNSAFE`; an unresolved, incomplete, failed, or unverified required
node makes it `UNKNOWN`; only complete and verified required nodes can produce
`SAFE`. Optional unknown nodes remain visible but do not claim required risk.

The CLI builds a local closure for every scan and adds bounded external
reference descendants when `--transitive` is explicitly enabled. Evidence and
attestations bind the complete graph and its digest. Verification compares the
reviewed and current canonical graphs and names changed, missing, or unexpected
nodes and edges. Runtime contracts can pin both root and closure digests before
the existing host gateway authorizes any operation.

`internal/derived` is a pure preprocessing boundary between immutable ingestion
and the analyzer registry. It constructs bounded alternative full-file views,
maps every transformed output range to original byte spans, and never performs
execution, network access, or model calls. The registry analyzes original bytes
first and then reuses eligible deterministic analyzers over derived views.
Derived evidence is additive; ambiguity or resource exhaustion degrades
coverage and therefore closure state.

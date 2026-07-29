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
source -> safe loader -> artifact + digest
                         ├-> analyzers -> findings + coverage + inspection ledger
contract ----------------┴-> verification
eval spec -> isolated adapter -> tool request -> host gateway -> enforcer -> host tool
                                  └-> bounded result -> adapter -> final output
trusted gateway records -------------------------------> trace + metrics
scan/eval evidence -> attestation -> policy decision
```

Core, scanner, semantic provider, policy engine, and eval harness have no
backwards dependencies. Providers cannot acquire tools through their interface.
The CLI composes modules and maps errors to stable exit codes.

Optional analysis is composed through one shared CLI configuration used by
scan, verification, attestation, policy, and installation. Tree-sitter AST
remains local. OSV, YARA, and semantic adapters are registered only by explicit
flags, so their coverage cannot be confused with the default offline scan.

`scan-all` is a discovery/composition layer, not a separate scanner: every
concrete skill receives its own artifact digest and complete analyzer ledger.
The scanner MCP service exposes the same path through a configured filesystem
root. Stdio is process-confined; HTTP is loopback-only and requires a
constant-time checked bearer token.

Assurance levels describe completed work, not safety: `UNVERIFIED`,
`VALIDATED`, `STATIC_ANALYZED`, `SEMANTIC_ANALYZED`,
`BEHAVIORALLY_EVALUATED`, `ATTESTED`, and `POLICY_APPROVED`.

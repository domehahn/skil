# Architecture

The public `pkg/skil` package contains stable models and narrow extension
interfaces. `internal/artifact` creates a canonical, immutable input view;
`internal/analyzer` runs independent read-only analyzers; `verification`
compares observed behavior with `SkillContract`; `eval` is the only execution
boundary; `policy` consumes results but never scans; `evidence` binds results to
digests; and `report` only serializes.

```text
source -> safe loader -> artifact + digest
                         ├-> analyzers -> findings + coverage
contract ----------------┴-> verification
eval spec -> AgentRuntime -> trace + metrics
scan/eval evidence -> attestation -> policy decision
```

Core, scanner, semantic provider, policy engine, and eval harness have no
backwards dependencies. Providers cannot acquire tools through their interface.
The CLI composes modules and maps errors to stable exit codes.

Optional analysis is composed per scan. Tree-sitter AST remains local. OSV,
YARA, and semantic adapters are registered only by explicit CLI flags, so their
coverage cannot be confused with the default offline scan.

Assurance levels describe completed work, not safety: `UNVERIFIED`,
`VALIDATED`, `STATIC_ANALYZED`, `SEMANTIC_ANALYZED`,
`BEHAVIORALLY_EVALUATED`, `ATTESTED`, and `POLICY_APPROVED`.

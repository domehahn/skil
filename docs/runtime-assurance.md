# Runtime assurance

Static assurance says what exact graph was reviewed. Runtime assurance ensures
that execution remains inside that reviewed boundary.

`SkillContract` can optionally carry `reviewed_root_digest` and
`reviewed_closure_digest`. Construct an enforcer with the current identities:

```go
enforcer := enforcement.NewWithAssurance(contract, currentRootDigest, currentClosureDigest)
```

If a configured pin is missing or differs, startup authorization fails closed
before any operation. Existing contracts and `eval.New(contract)` remain
source-compatible through `enforcement.New(contract)` when closure pins are not
configured.

After startup validation, every operation still crosses the host-owned gateway.
The enforcer checks declared network, filesystem, environment, command, tool,
MCP, and resource boundaries. Runtime dependency loads require an explicitly
pinned dependency identity/digest; a newly introduced dependency cannot inherit
trust from the root artifact. The trusted host, not an agent adapter, derives
operations and records the audit trace.

Digest pins prevent substitution of reviewed content, but do not make an
untrusted runtime safe by themselves. Native isolation, least-privilege host
tools, bounded outputs, secret handling, and re-verification at installation or
startup remain necessary. Dynamic persistence behavior is represented by
`PersistenceTestEvidence`; `confirmed_behavioral_persistence` is true only when
controlled data survives the explicit write/restart/read sequence.

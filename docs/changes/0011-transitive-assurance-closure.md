# Change 0011: Transitive agentic supply-chain assurance closure

## Problem

SKIL v0.3.0 records a digest-bearing graph for opt-in HTTPS reference scans,
but the graph is not yet a complete fail-closed trust boundary. Its digest
helper relies on caller ordering, incomplete descendants can still leave a
root scan CLEAR, attestation verification reports only a whole-graph mismatch,
and runtime closure pins do not bind the root or the reviewed graph identity.
Agent configuration, dependency registries, and persistent context are scanned
by separate analyzers but are not normalized consistently enough to participate
in policy and evidence decisions.

## Decision

Harden the existing `AssuranceClosure` and lifecycle rather than introduce a
parallel assurance system:

- use typed node kinds and analysis/verification/assurance states;
- canonicalize nodes, edges, limitations, and finding references before
  hashing, making digest computation independent of discovery order and cycles;
- derive root trust from every required node, with `SAFE`, `UNSAFE`, and
  `UNKNOWN` remaining distinct;
- make incomplete or unsafe required closure members prevent CLEAR/ALLOW;
- bind closure identity and completeness into existing attestations and report
  exact drift violations during verification;
- let runtime contracts optionally pin the reviewed root and closure digests,
  while retaining the existing per-resource digest pins;
- normalize agent execution, dependency-source, and persistent-state evidence
  into deterministic capability observations consumed by policy and evidence.

No analyzed content is executed, and ordinary static scans remain offline.
Existing JSON fields and public constructors remain valid; additions are
optional except that a present required closure now fails closed.

## Acceptance criteria

- equivalent closures have the same digest regardless of traversal order;
- required changed, missing, unresolved, unanalyzed, budget-limited, or blocked
  members prevent a trusted root result;
- closure verification identifies the exact node or edge that drifted;
- attestations bind root digest, closure digest, completeness, verification,
  and assurance state without claiming complete assurance for incomplete work;
- runtime authorization rejects configured root/closure drift and unreviewed
  runtime dependencies;
- Claude-compatible hooks and permissions, dependency registries, and
  persistent-memory/RAG behavior produce normalized observations;
- deterministic risk, policy, semantic monotonicity, and order independence are
  covered by executable tests;
- schemas, CLI output, architecture, security, attestation, runtime, benchmark,
  and configuration documentation match the implementation.

## Validation

```text
go test ./...
go test -race ./...
go vet ./...
make lint
```

Benchmark results are reported only when the repository benchmark can run
locally with its declared dependencies; no metric improvement is inferred from
new fixtures alone.

## Rollback

Revert this change record and the associated model, assurance, analyzer,
policy, schema, test, fixture, and documentation changes. Additive serialized
fields may be ignored by older consumers; contracts that opt into root/closure
runtime pins must remove those optional pins when rolling back.

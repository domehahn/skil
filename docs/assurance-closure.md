# Assurance closure

An assurance closure is the canonical graph of every artifact and privileged
surface required to trust a skill. It turns separate scanner observations into
one fail-closed decision boundary without introducing a second scanner or
policy engine.

## Graph model

The root is connected to local artifacts, nested artifacts, dependency
manifests and lockfiles, agent execution configuration, MCP configuration,
persistent-state surfaces, and runtime artifacts. With `--transitive`, bounded
external references and their descendants join the same graph. Nodes record
kind, source, digest, parent, depth, required/resolved/analyzed flags, analysis
and verification statuses, severity, verdict, and finding provenance. Edges
record relationships such as `contains`, `depends-on`, `configures`, `loads`,
and `references`.

Nodes and edges are sorted and deduplicated before SHA-256 hashing. Limitations
and finding references are canonicalized too. Equivalent graphs therefore have
the same digest regardless of traversal order, duplicate discovery, or cycles.
Changing a child, relationship, required status, analysis result, or verdict
changes the closure identity.

## States and propagation

- `SAFE`: every required node is resolved, fully analyzed, verified, and not
  blocked.
- `UNSAFE`: at least one required node has a blocking verdict or high/critical
  finding. Unsafe dominates unknown state.
- `UNKNOWN`: a required node is missing, unresolved, skipped, failed,
  incompletely analyzed, budget-limited, or unverified.

The aggregate also reports `complete`, `verified`, required/unresolved counts,
blocking finding count, maximum depth and severity, and explicit limitations.
Optional unresolved nodes stay visible but do not lower the required closure's
state.

## Detect → verify → decide → attest → enforce

1. The ordinary analyzer registry produces deterministic findings,
   observations, inspection coverage, budgets, and dependency identities.
2. Closure construction binds those results to local nodes and, when requested,
   external descendants. It never executes analyzed content.
3. Verification compares an attested/reviewed closure with the current closure
   and identifies the precise missing, unexpected, or changed node or edge.
4. Policy denies `UNSAFE` and `UNKNOWN` required closure states and budget
   exhaustion. Dependency source policy consumes canonical source identities.
5. Attestations embed the closure graph and summary, dependency inventory, and
   observation/dependency digests under the artifact subject digest.
6. Runtime contracts may pin reviewed root and closure digests; the host gateway
   then applies existing per-operation capability and resource authorization.

The default scan remains offline. External traversal is activated only with
`--transitive`; a reference that cannot be followed remains an explicit
`UNKNOWN` member instead of disappearing. See
[transitive scanning](transitive-scanning.md), [attestations](attestations.md),
and [runtime assurance](runtime-assurance.md).


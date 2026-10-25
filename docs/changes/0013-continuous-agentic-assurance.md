# Change 0013: Continuous Agentic Assurance foundations

Status: implemented with documented deferred integrations

## Requirements and acceptance criteria

1. Authority restrictions survive lifecycle boundaries or produce explicit drift evidence.
2. Child contexts never inherit `VERIFIED`; every security-relevant delta changes closure identity.
3. Planned work and nested budget allocations have explicit, bounded outcomes.
4. Runtime/LoC verification depends on observable effects, never self-report.
5. Configuration discovery distinguishes absent, partial, unsupported, and failed states and preserves valid siblings.
6. Evidence identities survive summaries and attestation; malformed completion cannot erase committed evidence.
7. New enforcement correlations require staged, benchmark-backed promotion.

Validation maps to tests in `internal/assurance`, `internal/completeness`, `internal/eval`, `internal/discover`, `internal/evidence`, `internal/identity`, `internal/policy`, and `internal/derived`, plus `benchmark/runner/test_release_delta.py`.

## Architecture and rollback

The change extends existing assurance, completeness, eval, discovery, evidence, identity, policy, and derived-view boundaries. It adds no service, network dependency, persistent migration, or execution path. Rollback is a source revert; attestation v1 remains supported.

## Security review

Assets are authorization constraints, evidence identity, runtime effects, and closure identity. Trust boundaries are parent→child, context compaction, agent→tool/MCP, runtime→observer, and parser→summary. Primary threats are authority broadening, evidence tampering/loss, false completeness, forged runtime verification, resource exhaustion, and configuration confusion. Controls are canonical digests, evidence-required graph edges, explicit incomplete states, bounds, no host execution, and negative/property tests.

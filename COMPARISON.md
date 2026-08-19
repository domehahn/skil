# How skil compares

This document states what skil verifiably does, backed by links to the tests
and evidence artifacts that make each claim checkable — not a "why we're
better" pitch, and not a named comparison against any specific third-party
product.

Consistent with this repository's independent-product-identity policy
(`tests/independent_identity_test.go`, `compat/external-scanner/README.md`),
skil does not name or brand-compare itself against specific commercial or
open-source scanners in its own documentation. Where this document describes
a difference from "typical skill scanners," it means the general shape of
that class of tool, not a specific product — and every specific number below
is either skil's own, reproducible from this repository, or attributed to a
neutral, versioned specification (ASPS) rather than to another vendor's
marketing.

## What skil is

Most agent-skill security tools answer one question: *does this artifact
contain a suspicious pattern?* skil answers a longer chain of questions, and
keeps each answer as separate, digest-bound evidence rather than folding
everything into one finding list:

```text
contract ─┐
analysis ─┼─> verification ─> policy ─> evidence ─> attestation ─> enforcement
eval ─────┘
```

- **What did the artifact declare** it needs (contract)?
- **What did static/semantic analysis actually observe** it doing (analysis)?
- **What did controlled execution actually do** (eval)?
- **Does the observed behavior match the declaration** (verification)?
- **Is this specific, digest-identified artifact allowed** in this
  environment (policy)?
- **Can we prove, later, exactly what was checked and decided** (evidence,
  attestation)?
- **At runtime, is this exact artifact still permitted to do this exact
  thing** (enforcement) — not "was it scanned once," but "is this specific
  operation, by this specific principal, under this specific contract,
  authorized right now"?

Concretely, skil's runtime `Enforcer` (`pkg/enforcement`) denies an operation
that: exceeds a resource/token/mutation budget it is tracking live
(`Ledger()`); retries a non-idempotent destructive/irreversible effect
(`verifyIdempotencyOnRetry`); promotes untrusted data into an
authorization-required context without an explicit, recorded verification
step (`verifyTrustBoundary`); or loads a runtime dependency whose observed
digest doesn't match what was reviewed and pinned in advance
(`verifyReviewedClosure` — the TOCTOU gap between "we scanned version X" and
"the process actually executed version Y"). Every decision — allow or deny —
is recorded as a structured `DecisionRecord` (capability, target, digest,
decision, reason; never raw arguments or model reasoning), so "why was this
denied" is answerable after the fact without re-running anything.

That's a materially different problem than pattern-matching a file, and it's
why comparing skil to a scanner purely on rule count understates what it
does — and equally, why comparing it on architecture alone overstates
maturity that hasn't been independently measured yet (see
[What isn't independently benchmarked](#what-isnt-independently-benchmarked-yet)).

## Verifiable capability matrix

Every row links to the code or test that makes the claim checkable — run the
linked command or test yourself rather than taking the row on faith.

| Capability | Evidence |
|---|---|
| 120-property, 15-domain agentic security taxonomy (ASP-01 … ASP-15), each property with an invariant, a detection method, and a minimum-evidence bar | `compat/asps/asps-registry.json`, schema-validated by `compat/asps/asps_conformance_test.go` |
| Per-domain conformance scoring against that taxonomy, not just a checklist | `skil conform --profile <name>` (`internal/conformance`) |
| Static analysis: pattern, Tree-sitter AST (Python/JS/TS/TSX/Bash), multi-hop taint tracking, dependency inventory (Go/Python/npm/Cargo/RubyGems/Maven), MCP protocol conformance, Unicode/bidi/confusable/tag-smuggling detection, native malware signatures + YARA | `internal/analyzer/` (one file per domain), each with its own positive/negative test suite |
| Multi-agent delegation graph analysis: circular delegation, privilege-escalating delegation (`child scope ⊆ parent scope` as an actual computed invariant, not a description) | `internal/analyzer/multi_agent.go` + `multi_agent_test.go` |
| Credential/identity flow checks: missing audience binding, overbroad OAuth scope, non-expiring tokens, consent-scope violations | `internal/analyzer/credential_flow.go` |
| Purpose-aware data classification: sensitive-data purpose-limitation violations, unbounded retention, unconstrained field collection | `internal/analyzer/data_classification.go` |
| Declared-vs-observed capability verification (does the artifact use more, or different, capabilities than it declares) | `internal/verification` |
| Runtime capability enforcement with a real budget ledger (tokens, network bytes, tool calls, external mutations, delegation/recursion depth), trust-boundary promotion control, and TOCTOU-safe dependency-closure digest binding | `pkg/enforcement/enforcer.go` + `enforcer_test.go` |
| Policy-level revocation (signer key, artifact digest, or skill name/version) that overrides prior trust rather than merely withholding new trust | `internal/policy` (`RevokedSignerKeyIDs`/`RevokedArtifactDigests`/`RevokedSkills`) |
| Structured, digest-bound decision records for every allow/deny — auditable without re-running the scan, and never containing raw arguments or chain-of-thought | `pkg/skil/enforcement.go` (`DecisionRecord`) |
| DSSE/in-toto provenance, package signing, digest-bound attestation, lockfile-pinned install/update lifecycle | `internal/signing`, `internal/contracts`, `docs/` (provenance/attestation sections) |
| Deterministic mutation-testing harness measuring how many lexical/encoding variants (case, whitespace, homoglyph, zero-width, leetspeak) of a fixture still trigger the same rule | `internal/mutation` + `internal/analyzer/mutation_robustness_test.go` |
| A loopback-only admission endpoint wrapping the scan+policy pipeline for non-CLI callers (registries, marketplaces, CI systems) | `internal/cli/admission.go` (`skil admission serve`) |
| Zero known external-only detection gaps against a fixed, versioned differential corpus (173 fixture entries across 74 ASPS properties: 159 FULL, 12 deliberate-design-difference, 2 provider-backed, 0 partial, 0 missing) | `compat/external-scanner/`, full property-level rationale in `docs/external-scanner-feature-parity.md` |

## What isn't independently benchmarked yet

In the interest of the same honesty this document asks for elsewhere:

- The differential comparison above is pinned to one specific external
  scanner commit at one point in time. Skill-security tooling in this space
  moves fast; the comparison shows skil had no known detection gap against
  that pinned snapshot's property corpus — it is **not** a claim that skil
  is a superset of whatever that tool's current release does today. Re-running
  the harness (`compat/external-scanner/run_differential.py`) against a
  current checkout is the only way to make that check current.
- A vendor-neutral precision/recall/F1/false-positive-rate benchmark against
  skil and two OSS reference scanners now exists (`benchmark/`, evaluated
  weekly by `.github/workflows/benchmark.yml`), but **it has zero
  gold-reviewed fixtures so far** — its ground-truth model requires at least
  two independent human reviewers per fixture before any number counts as a
  headline metric, and only one person has reviewed anything to date. Until
  that changes, its headline metric correctly reads `"n/a"` for every tool;
  see `benchmark/README.md`'s "Call for reviewers" section if you'd like to
  help change that.
- Community size, external contributor count, and independent third-party
  security review are not something a repository can assert about itself;
  they aren't claimed here.

If you build or find a neutral benchmark that includes skil, or you find a
gap in the claims above, please open an issue — see
[CONTRIBUTING.md](CONTRIBUTING.md).

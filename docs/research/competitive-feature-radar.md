# Competitive Feature Radar: Continuous Agentic Assurance

Status date: 2026-09-17  
Repository baseline: `93d3daaad33fd216b2c7584e8d6704e67f9ad55b` (`v1.0.0-rc1` worktree, before this change)  
Upstream baselines: NVIDIA SkillSpector `v2.11.2` (`69dcdfb`), Cisco Skill Scanner `2.1.0` (`a24df34`), Tencent AI-Infra-Guard `v4.6.1` (`e68bc5d`), Snyk Agent Scan `v0.6.3`.

This document is the required pre-implementation gap matrix. `COMPLETE` means the capability is implemented and connected to normal assurance flows; a type or isolated CLI demonstration alone is not complete. Competitor columns record motivating concepts, not code provenance or proven parity. SKIL implementations remain original.

Status vocabulary: `COMPLETE`, `PARTIAL`, `MISSING`, `NEEDS_HARDENING`, `NEEDS_INTEGRATION`, `NOT_APPLICABLE`.

| Capability | Initial SKIL status | NVIDIA | Cisco | Tencent | Snyk | Security impact | Assurance-stage fit | Repository evidence / planned test |
|---|---|---|---|---|---|---|---|---|
| Constraint integrity | MISSING | — | Policy-oriented scanning | Agent/runtime evaluation | Consent boundaries | Prevent silent authority weakening | Verify, Decide, Attest | Add first-class constraints, boundary comparison, monotonicity tests |
| Authorization continuity | MISSING | — | — | Context-preservation lessons | Per-server consent | Preserve restrictions through lifecycle changes | Verify, Enforce | Add workspace/session/compaction/subagent/tool transitions |
| Loss-of-control verification | MISSING | — | Behavioral analysis | Multi-turn agent red teaming | Observable MCP interaction | Detect actual unauthorized effects | Verify, Observe | Add original deterministic effect-oracle scenarios |
| Assurance completeness | PARTIAL | Incomplete reference accounting | Pipeline/analyzer accounting | Empty-result and compaction fixes | Operational failure codes | Prevent false-clean results | Detect, Decide | `internal/completeness` exists but CLI uses synthetic counts/identities |
| Resolution completeness | PARTIAL | Runtime-selected executable reporting | Python semantic resolution | Parser hardening | Inspection failures | Separate syntax from execution identity | Detect, Verify | `ResolutionState` exists; not wired broadly into scanner identities |
| Analysis work accounting | NEEDS_HARDENING | Reference accounting | Analyzer pipeline | Scan-note/result metadata | Discovery/inspection failures | Account for every planned unit | Detect, Attest | `WorkLedger` is aggregate-only and synthetic in `AnalyzeCompleteness` |
| Hierarchical analysis budgets | MISSING | Bounded processing | Analyzer limits | Resource-bounded scanners | Timeouts | Bound child work and expose exhaustion | Detect, Verify | Extend existing `AnalysisBudget`; parent/child property tests |
| Hierarchical session/subagent assurance | MISSING | — | — | Agent scan | Agent discovery | Prevent inherited verification across principals | Verify, Attest | Add `AssuranceContext`, delta closure, child invalidation tests |
| Authority/delegation flow | PARTIAL | — | Cross-skill/correlation | Agent scan | Toxic-flow concepts | Prove reachable escalation without speculation | Detect, Decide | Extend `internal/attackpath`; bounded cycle-safe authority graph |
| Runtime evidence verification | PARTIAL | — | Behavioral engine | Agent red teaming | Live MCP inspection | Promote only independently observed effects | Verify, Observe | Runtime receipts exist; no generic runtime-observation promotion path |
| Behavioral attestation | PARTIAL | — | Behavioral analyzer | LLM/agent evaluation | Analysis API | Invalidate stale behavior claims | Attest | Eval metrics exist; attestation lacks full suite/constraint/runtime binding |
| Observer identity | NEEDS_HARDENING | Tool/version identity | Analyzer/provider identity | Scan metadata | Release/signature artifacts | Identify evidence producer | Attest | Type exists; CLI currently injects placeholder digests and version |
| Executable identity | NEEDS_HARDENING | Executable reconstruction | Callable resolution | Multi-language scanning | MCP entity identity | Canonicalize security-sensitive targets | Detect, Verify | Cross-ecosystem type exists but lacks resolution state and broad integration |
| Floating/mutable component identity | PARTIAL | Supply-chain checks | Dependency checks | Skill/package scanning | Component signatures | Detect resolved-identity drift | Detect, Attest | Version comparison and lockfiles exist; general constraint classification/drift binding absent |
| Agent/MCP configuration dialects | PARTIAL | Codex/Claude skills | — | MCP scan | Broad agent discovery | Avoid invisible local attack surface | Detect | Discovery covers many tools but not Copilot and loses remote transport identity |
| Discovery completeness | MISSING | Input/accounting fixes | Lenient/error behavior | Empty-result incomplete marker | Failure codes/full discovery | Distinguish unsupported from absent | Detect, Decide | Existing discovery returns components/errors, not per-location coverage |
| Syntax ownership | PARTIAL | Documentation parser-limit fixes | Structured analyzers | Compaction preservation | Skill/MCP parsing | Reduce prose false positives without hiding embedded code | Detect | Derived views preserve mappings; no explicit ownership classification |
| Evidence preservation | NEEDS_INTEGRATION | Finding/reference preservation | Correlation pipeline | Compaction finding preservation | Risk evidence fields | Prevent identity loss across transforms | Verify, Attest | Result commit type exists but no reusable required-field projection invariant |
| Result commit semantics | NEEDS_HARDENING | Incomplete result reporting | Pipeline results | Result metadata/scan notes | Operational failures | Keep valid evidence on malformed completion | Verify, Decide | Current protocol stores strings and coarse finish tags, not validated/committed states |
| Model/provider identity assurance | PARTIAL | Provider configuration | Multi-provider analyzers | Relay checker/fingerprint research | Versioned analysis API | Detect provider/model drift without overclaiming | Verify, Attest | Provider assurance exists; no defensible observed fingerprint claim |
| Typed decision promotion | MISSING | Risk categories | CEL/pipeline correlations | Risk taxonomy | Scored risk indicators | Prevent immature rules becoming enforcement-critical | Decide, Enforce | Add typed facts and EXPERIMENTAL→SHADOW→BENCHMARKED→ENFORCE gates |
| Competitive release delta automation | PARTIAL | Pinned/rolling adapter | Pinned/rolling adapter | No adapter | No adapter | Detect upstream detection deltas continuously | Detect, Re-Assure | Benchmark has NVIDIA/Cisco adapters and digests; lacks release-delta report and Tencent/Snyk coverage |
| Rule/policy supply-chain integrity | PARTIAL | Rules/configuration | Custom taxonomy/policy | Rule corpus | Remote analysis version | Prevent silent loss of controls | Detect, Decide | Embedded schemas/rules exist; required-pack validation not universally closure-bound |
| Canonical MCP endpoint identity | MISSING | — | — | MCP scanner | MCP signatures/transports | Bind remote server identity and topology | Detect, Attest | Current discovery retains only stdio command/args |
| Exact identity before similarity | NEEDS_HARDENING | Package checks | Dependency checks | Skill supply chain | Component signatures | Avoid false typosquat classifications | Detect | Registry canonicalization exists; invariant needs explicit cross-domain test |
| Attestation v2 | MISSING | Reports/SARIF | Reports/SARIF | Result metadata | Signed release artifacts | Bind continuous-assurance inputs | Attest | v1 evidence/attestation cannot represent all requested dimensions |
| Enforcement on evidence-backed state | PARTIAL | CI thresholds | Severity gates | CI integration | CI failure modes | Fail closed only on proven state | Enforce | Existing policy handles completeness/budget; new authority/drift/child states absent |
| Dedicated benchmark families | PARTIAL | Detection corpus | Detection/behavioral | SkillTrustBench/red team | Risk evaluation | Avoid metric conflation | Verify | Existing detection/competitive/behavioral tests; LoC/preservation/config families absent |
| Scanner self-assurance and determinism | PARTIAL | Parser/accounting regressions | Analyzer hardening | Parser/schema fixes | Failure reporting | Attacker input must not increase assurance | All | Existing torture, fuzz, bounds, closure-order tests; new graph/context/commit properties needed |

## Initial implementation decision

The repository is ready with caveats. Existing closure, evidence, budget, discovery, runtime receipt, identity, and benchmark primitives should be extended in place. The smallest useful security increment is: (1) truthful completeness/work/budget primitives, (2) authorization and child-context continuity, (3) deterministic runtime/LoC observations, and (4) endpoint/component identity plus attestation bindings. Live model fingerprinting is intentionally excluded until a reproducible method and confidence calibration exist.

## Upstream evidence

- NVIDIA SkillSpector releases: <https://github.com/NVIDIA/SkillSpector/releases/tag/v2.11.2>
- Cisco Skill Scanner releases: <https://github.com/cisco-ai-defense/skill-scanner/releases/tag/v2.1.0>
- Tencent AI-Infra-Guard releases: <https://github.com/Tencent/AI-Infra-Guard/releases/tag/v4.6.1>
- Snyk Agent Scan releases: <https://github.com/snyk/agent-scan/releases/tag/v0.6.3>

Upstream status must be rechecked before each release-delta benchmark. A feature mention above is not an independently measured parity claim.

## Post-implementation closure

| Capability | Final status | Evidence / residual scope |
|---|---|---|
| Constraint integrity | IMPLEMENTED | Digest-bound constraints and five-state boundary comparison in `internal/assurance`; weakening/loss fuzz and unit tests |
| Authorization continuity | IMPLEMENTED | Explicit workspace/session/compaction/subagent/tool boundary parameter and drift evidence; integration callers must supply each lifecycle transition |
| Loss-of-control verification | IMPLEMENTED | Original factor model, effect oracles, seven metrics, nine isolated canary strategies, and self-report-vs-effect tests |
| Assurance completeness | HARDENED | Standalone command no longer manufactures `FULL`; Security Evidence v1 fails closed without inspection/closure evidence |
| Resolution completeness | HARDENED | Cross-ecosystem executable identity carries explicit resolution; broad analyzer emission remains incremental |
| Analysis work accounting | IMPLEMENTED | Per-unit detailed ledger and digest with strict accounted-outcome invariant; legacy aggregate ledger retained |
| Hierarchical analysis budgets | IMPLEMENTED | Parent-attributed child reservations with remaining-budget cap and exhaustion evidence fields |
| Hierarchical session/subagent assurance | IMPLEMENTED | `AssuranceContext`, parent identity, delta closure, and no inherited verification invariant |
| Authority/delegation flow | IMPLEMENTED | Evidence-backed, cycle-safe, node/edge/depth-bounded reachability and escalation results |
| Runtime evidence verification | PARTIAL | Generic runtime observation promotion is implemented; direct promotion into every legacy Evidence Graph builder is deferred |
| Behavioral attestation | IMPLEMENTED | Attestation v2 binds suite, runtime, LoC, constraint, model/provider, and observer identities |
| Observer identity | HARDENED | Runtime version/commit/binary digest replace placeholders; unknown policy/analyzer/config inputs remain explicitly `unknown` |
| Executable identity | HARDENED | Resolution-bearing Python/JS/TS/shell/PowerShell/MCP/agent/native identity with CallableIdentity compatibility |
| Floating/mutable component identity | IMPLEMENTED | Constraint classification, resolved identity digest, drift result, and exact-before-similarity invariant |
| Agent/MCP configuration dialects | HARDENED | Adapter contract plus generalized standard dialect handles Copilot local/HTTP/SSE without a separate parser hack |
| Discovery completeness | IMPLEMENTED | Per-location five-state coverage in CLI JSON; malformed sibling isolation and unsupported transport tests |
| Syntax ownership | PARTIAL | File and Markdown prose/fence ownership preserve offsets; full JSON/YAML/HTML parser-backed regions deferred |
| Evidence preservation | PARTIAL | Required security projection and downgrade/loss verifier implemented; every legacy report transform is not yet migrated |
| Result commit semantics | HARDENED | Receive/validate/commit/completion states preserve evidence across malformed completion |
| Model/provider identity assurance | PARTIAL | Honest requested/reported/baseline/fingerprint fields can be attested; unreliable statistical fingerprinting is intentionally absent |
| Typed decision promotion | IMPLEMENTED | Typed fact kinds and benchmark/determinism/monotonicity-gated promotion lifecycle |
| Competitive release delta automation | PARTIAL | Same-corpus old/new/SKIL delta engine and tests; Tencent/Snyk executable adapters deferred |
| Rule/policy supply-chain integrity | IMPLEMENTED | Rule schema/ID/version/capability/decision/provenance/digest validation with required-rule fail-closed behavior |
| Canonical MCP endpoint identity | IMPLEMENTED | Transport, command/args or URL, TLS/auth/schema fields and canonical identity digest |
| Exact identity before similarity | IMPLEMENTED | Exact known identity exits similarity classification; regression test included |
| Attestation v2 | IMPLEMENTED | Versioned schema and deterministic bound-input verification; CLI emission remains opt-in library integration |
| Enforcement on evidence-backed state | IMPLEMENTED | Candidate fail-closed reasons emit only when the caller marks state evidence-verified |
| Dedicated benchmark families | PARTIAL | Completeness, LoC, preservation, config compatibility, and release-delta tests exist; no fabricated before/after scores |
| Scanner self-assurance and determinism | HARDENED | New monotonicity, ordering, budget, collision/downgrade, context, and malformed-sibling tests extend existing torture suite |

## Deferred work register

| Item | Reason | Security consequence | Dependency | Recommended next step |
|---|---|---|---|---|
| Runtime promotion in every Evidence Graph path | Multiple legacy graph construction paths need a versioned migration rather than parallel code | Runtime observations are attestable but some reports remain `OBSERVED` until explicitly correlated | Evidence Graph schema/API migration | Add one canonical `PromoteWithRuntimeObservation` entry point and migrate builders |
| Full structured syntax ownership | Reliable JSON/YAML/HTML ownership needs parser-node source ranges, not regex guesses | Some prose/config ambiguity still degrades precision or completeness | Existing tree-sitter/structured parser adapters | Emit `OwnedSpan` from parser nodes and feed it into analyzer routing |
| End-to-end projection migration | Existing v1 reports predate the security projection contract | Preservation is testable at new boundaries but not mechanically asserted at every legacy transform | Report and signing schema versioning | Add projection digest to report, session handoff, and v2 CLI attestation paths |
| Statistical model fingerprinting | No defensible reproducibility/confidence baseline was established | Provider substitution can be attested when externally identified but is not inferred from behavior | Calibrated research corpus and operational thresholds | Run blinded provider drift research; ship only if false-identification bounds are acceptable |
| Tencent and Snyk executable benchmark adapters | Current safe, stable, pinned machine-readable invocation contracts were not established locally | Automated release delta coverage remains strongest for existing NVIDIA/Cisco adapters | Stable pins, licenses, safe isolated execution, normalized output contracts | Add adapters only after reproducible dry-run fixtures and legal/security review |
| All legacy CLIs emitting Attestation v2 | Immediate replacement would break v1 consumers and toolchain contracts | New bindings are available but not default in every command | Compatibility rollout and downstream consumer support | Add `--attestation-version 2`, cross-tool contract tests, then staged default promotion |
| Live canary execution for every target | Host execution is forbidden and several effects require dedicated isolated fixtures | Strategy contracts exist; coverage is incomplete until an isolated runtime supplies observations | `skrun`/isolated adapter fixtures and controlled sinks | Implement one sandboxed fixture per canary kind and bind execution receipts |

No item above is treated as clean, complete, or parity-equivalent while deferred.

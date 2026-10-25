# 0016: Next-Generation Continuous Agentic Assurance

- **Status**: Implemented & Verified
- **Lifecycle**: `DETECT → VERIFY → DECIDE → ATTEST → ENFORCE → OBSERVE → RE-ASSURE`
- **Guiding Principle**: *Never fall behind on detection. Lead on assurance.*

---

## 1. Architecture Overview & Lifecycle Integration

This change evolves SKIL from static/hybrid skill assurance and session-level receipts into a **Continuous Agentic Assurance Platform** capable of verifying, authorizing, attesting, enforcing, observing, and re-assuring live agentic AI execution without introducing duplicate graphs, gateways, policy engines, or signing primitives.

| Lifecycle Stage | Package & Component Integration | Key Types & Entrypoints |
| :--- | :--- | :--- |
| **DETECT** | `internal/analyzer`, `internal/attackpath` | Multi-agent interaction graph (`AGENT`, `SUBAGENT`, `SKILL`, `TOOL`, `MCP_SERVER`, `CREDENTIAL`, `DATA_STORE`, `EXTERNAL_ENDPOINT`, `RAG_SOURCE`, `MEMORY_STORE`, `POLICY`, `RUNTIME_ENVIRONMENT`, `AUTHORIZATION`, `EVIDENCE`) and typed edges (`CAN_INVOKE`, `CAN_READ`, `CAN_WRITE`, `CAN_DELEGATE`, `RETRIEVES_FROM`, `TRUSTS`, `EXPOSES`, `FLOWS_TO`, `AUTHORIZED_BY`, `OBSERVED_EXECUTION`). |
| **VERIFY** | `internal/attackpath`, `internal/redteam` | `VerifyAttackPathInIsolation`, `EvaluatePathConfidence` (`HYPOTHETICAL`, `STATICALLY_SUPPORTED`, `DYNAMICALLY_TESTED`, `VERIFIED_EXPLOITABLE`, `VERIFIED_BLOCKED`, `INCONCLUSIVE`), `RunAdaptiveAssuranceLoop`, `ValidateCandidateTest`. |
| **DECIDE** | `internal/policy`, `internal/continuous`, `internal/evidence` | `AssuranceValidityConditions`, `EvaluateAttackPathRisk` (separating verified facts from `HeuristicRiskEstimate`), `ImportCertificateForEnvironment`. |
| **ATTEST** | `internal/evidence`, `internal/receipt`, `internal/signing` | `PortableAssuranceStatementV1`, `PortableCertificatePredicateV1`, `SignedPortableCertificate` (DSSE + in-toto v1), `ExecutionAuthorization`. |
| **ENFORCE** | `internal/receipt`, `internal/runtimeproxy`, `internal/mcpinterceptor` | `ExecutionGateway.ValidateAuthorization`, `ExecutionGateway.AuthorizeAndExecute`, `CaptureFileIdentity`, `VerifyFileIdentityAtUse`, `NonceLedger`, `OperationEnforcementReceipt`. |
| **OBSERVE** | `internal/continuous`, `internal/drift`, `internal/receipt` | `DriftEvent`, `EnvironmentSnapshot`, `VerifyOperationReceipt`, `AssuranceTransitionRecord` (`AuditLog`). |
| **RE-ASSURE** | `internal/continuous`, `internal/redteam` | `Engine.IngestDriftEvent`, `Engine.Reconcile`, `Engine.PlanSelectiveReAssurance`, `GenerateCandidateFromVerifiedAttackPath`. |

---

## 2. Five Innovations — API & Schema Documentation

### 2.1 Innovation One: Proof-Carrying Agent Execution (`internal/receipt/authorization.go`)
- **`ExecutionAuthorization`**: Ed25519 DSSE-signed (`application/vnd.skil.execution-authorization.v1+json`), single-use, operation-bound authorization token binding:
  - `AuthorizationID`, `SubjectID`, `SubjectDigest`, `AgentID`, `SessionID`, `ParentAgentID`
  - `ToolOrServerID`, `RequestedCapability`, `EffectiveScope`, `AllowedTargets`
  - `OperationID` (`CanonicalOperationID`), `ArgumentDigest` (`CanonicalArgumentDigest`)
  - `PolicyID`, `PolicyDigest`, `DecisionID`, `AssuranceState`, `AssuranceEvidenceDigest`
  - `IssuerID`, `AudienceID`, `IssuedAt`, `ExpiresAt`, `Nonce`, `SingleUse`
  - `FileBinding` (`FileIdentityBinding`) and `MCPBinding` (`MCPInvocationBinding`)
- **Zero-Secret Guarantee**: `ContainsSensitiveCredentialMaterial` rejects raw API keys, bearer tokens, private keys, or secret assignments before signing.
- **TOCTOU & Subagent Separation**:
  - `CaptureFileIdentity` and `VerifyFileIdentityAtUse` verify canonical workspace containment, symlink-free resolution, size, mode, and SHA-256 content digest immediately before execution, recording `ResidualRisk` when OS-level atomic file-handle binding (`openat2`) is unavailable.
  - Parent agent authorizations never transfer to child subagents (`auth.AgentID != req.AgentID` fails closed).
- **`OperationEnforcementReceipt`**: Distinguishes `AUTHORIZED`, `ATTEMPTED`, `ACCEPTED`, `EXECUTED`, `DENIED`, `FAILED`, `TIMED_OUT`, and `UNKNOWN`. HTTP 200 transport status without protocol-level `Accepted` acknowledgment is recorded as `ATTEMPTED` (`EnforcementUnverified`), never `EXECUTED`.

### 2.2 Innovation Two: Continuous Re-Assurance Engine (`internal/continuous/engine.go`)
- **15 Typed Assurance Dependencies (`AssuranceDependencyKind`)**:
  `skill_content_digest`, `agent_config`, `model_identity`, `provider_identity`, `tool_schema`, `mcp_server_identity`, `dependency_version`, `package_digest`, `runtime_capabilities`, `policy_version`, `verification_environment`, `credential_scope`, `rag_data_source`, `memory_state`, `external_service_identity`.
- **Single Evidence Graph Projection**: `AttachAssuranceDependenciesToGraph` attaches `assurance-dependency` nodes and `depends-on-assurance` edges directly into `skil.EvidenceGraphSummary`.
- **Event-Driven & Periodic Reconciliation**:
  - `Engine.IngestDriftEvent` immediately transitions affected subjects to `ProofInvalidated`, revokes dependent policy decisions, and blocks new operations via `receipt.AssuranceValidityOracle`.
  - `Engine.Reconcile(EnvironmentSnapshot)` detects missed drift notifications; if `MaxReconciliationInterval` elapses without reconciliation, `IsAssuranceValid` fails closed (`ProofStale`).
  - `RetroactivePreventionClaimed` is always `false`.
- **Selective Re-Assurance**: `Engine.PlanSelectiveReAssurance` re-runs only controls mapped to drifted dependencies while forbidding cache reuse across incompatible subject, source, artifact digest, provider, tool schema, policy, or verification environment dimensions.

### 2.3 Innovation Three: Verified Multi-Agent Attack Paths (`internal/attackpath/verified.go`)
- **Evidence-Gated Confidence States (`AttackPathConfidence`)**:
  - `HYPOTHETICAL`: Graph reachability only.
  - `STATICALLY_SUPPORTED`: Backed by deterministic static findings/observations.
  - `DYNAMICALLY_TESTED`: Executed in an isolated harness.
  - `VERIFIED_EXPLOITABLE`: Confirmed by host-verified external observation (`ExternallyObserved && ObserverDigest != ""`) in an isolated sandbox with synthetic canary tokens (`SYNTHETIC-CANARY-*`) and controlled loopback/sandbox destinations.
  - `VERIFIED_BLOCKED`: Confirmed blocked by runtime enforcement in an isolated harness.
  - `INCONCLUSIVE`: Incomplete or non-reproducible run.
- **LLM Guardrail**: `EvaluatePathConfidence` guarantees that `LLMProposed` or `LLMReasoningOnly` paths can never be promoted to `VERIFIED_EXPLOITABLE` or `VERIFIED_BLOCKED`.
- **Fact vs. Heuristic Separation**: `EvaluateAttackPathRisk` separates verified findings/observations from `HeuristicRiskEstimate`.

### 2.4 Innovation Four: Adaptive Adversarial Assurance (`internal/redteam/adaptive.go`)
- **8 Deterministic Trigger Kinds**: `new_finding`, `changed_skill`, `new_mcp_capability`, `changed_trust_boundary`, `threat_intelligence`, `historical_incident`, `failed_verification_attempt`, and `verified_attack_path`.
- **Strict Candidate Validation (`ValidateCandidateTest`)**: Enforces target confinement, capability allowlists, resource/timeout bounds, mandatory sandbox isolation (`RequireIsolation && Spec.Containment.Required`), scratch cleanup, and zero production credentials.
- **Closed-Loop Feedback (`RunAdaptiveAssuranceLoop`)**:
  - Reproduced exploits become `RegressionFixture` entries.
  - Verified blocked attacks become `TestedControlEvidence` entries.
  - Inconclusive runs remain in `InconclusiveTests`.
  - `CoverageDelta` measures newly verified security properties beyond baseline, never raw test count.

### 2.5 Innovation Five: Portable Agent Assurance Certificate (`internal/evidence/portable.go`)
- **Standards-Based Format**: DSSE Ed25519 envelope (`application/vnd.in-toto+json`) over an in-toto Statement v1 (`https://in-toto.io/Statement/v1`) with predicate `https://skil.security/assurance-certificate/v1`.
- **Offline Verification (`VerifyPortableCertificateOffline`)**: Verifies artifact digest, DSSE signature, trusted producer/signer roots, subject binding across all `EvidenceManifest` entries, canonical `CertificateDigest`, and validity window without network calls.
- **Strict Verdict Separation**:
  - `CryptographicallyValid`: Signature, digest, trust root, and temporal validity pass.
  - `SubjectSafe`: `CryptographicallyValid && AssuranceState == SAFE && AssuranceOutcome == COMPLETE && CoverageSummary.Complete && OutcomeProof.Validate() == nil`.
  - `PolicyAccepted`: `SubjectSafe` plus satisfaction of `LocalVerifierPolicy`.
- **Cross-Environment Portability (`ImportCertificateForEnvironment`)**: Preserves upstream producer/scanner/policy provenance while evaluating local environment constraints, required verification methods, coverage thresholds, revocation lists, and dependency drift.

---

## 3. Security Threat Model & Remaining Limitations

- **Threats Mitigated**:
  1. Confused-deputy and replay attacks on tool/MCP execution (mitigated by operation-bound single-use `ExecutionAuthorization` and `NonceLedger`).
  2. Parent-to-subagent privilege inheritance (mitigated by strict `AgentID` binding and scope subset enforcement).
  3. Post-attestation runtime drift across skills, MCP schemas, RAG corpora, memory stores, models, and policies (mitigated by `continuous.Engine` + `ExecutionGateway` oracle).
  4. Unverified or hallucinated attack paths being treated as confirmed exploits (mitigated by `EvaluatePathConfidence` and `ValidateSyntheticSafety`).
  5. Cryptographically valid attestations for `UNSAFE` or `PARTIAL` artifacts being accepted as safe (mitigated by `VerifyPortableCertificateOffline` separating `CryptographicallyValid`, `SubjectSafe`, and `PolicyAccepted`).
- **Explicit Residual Risks & Limitations**:
  - Where OS-level atomic file handle execution (`openat2` / descriptor-bound exec) is unavailable on the host OS, `FileIdentityBinding` performs pre-execution path/symlink/SHA-256 re-verification and records `ResidualRisk: "pre-execution stat+sha256 verified; kernel-level atomic descriptor execution not bound"`.
  - Drift invalidation blocks future operations and revokes active decisions immediately upon ingestion or reconciliation, but cannot retroactively undo side effects of operations that already completed before drift occurred (`RetroactivePreventionClaimed: false`).

---

## 4. Backward Compatibility & Release Readiness

- **Backward Compatibility**: 100% additive. Existing `SecurityEvidenceV1`, `AttestationV2`, `SKRunReceiptV1`, `skil.ScanResult`, and `skil.EvidenceGraphSummary` schemas and CLI commands remain fully compatible.
- **Validation Suite**:
  - `go test ./...` — PASS
  - `go test -race ./...` — PASS
  - `go vet ./...` — PASS
  - `go build -buildvcs=false ./...` — PASS

---

## 5. Final Implementation Matrix

| Capability | Before | After | Tests | Remaining Gaps |
| :--- | :--- | :--- | :--- | :--- |
| **1. Proof-Carrying Agent Execution** (`ExecutionAuthorization`, TOCTOU file/MCP bindings, `NonceLedger`, `ExecutionGateway`, `OperationEnforcementReceipt`) | `PARTIAL` (session-level `SKRunReceiptV1` & static `ToolGrantToken`) | `COMPLETE` (`internal/receipt/authorization.go`) | `internal/receipt/authorization_test.go`, `internal/verification/continuous_invariants_test.go` | OS kernel descriptor-bound exec (`openat2`) is platform-dependent; residual risk is explicitly recorded in `FileIdentityBinding.ResidualRisk`. |
| **2. Continuous Re-Assurance Engine** (15 `AssuranceDependencyKind`s, Evidence Graph projection, `IngestDriftEvent`, `Reconcile`, `PlanSelectiveReAssurance`) | `PARTIAL` (digest-only pin check in `internal/continuous/state.go`) | `COMPLETE` (`internal/continuous/engine.go`) | `internal/continuous/engine_test.go`, `internal/verification/continuous_invariants_test.go` | None. |
| **3. Verified Multi-Agent Attack Paths** (Extended nodes/edges, 6 `AttackPathConfidence` tiers, `VerifyAttackPathInIsolation`, `ValidateSyntheticSafety`, `EvaluateAttackPathRisk`) | `PARTIAL` (4 node/edge types, static BFS in `internal/attackpath/graph.go`) | `COMPLETE` (`internal/attackpath/verified.go`) | `internal/attackpath/verified_test.go`, `internal/verification/continuous_invariants_test.go` | None. |
| **4. Adaptive Adversarial Assurance** (8 trigger kinds, `ValidateCandidateTest`, `RunAdaptiveAssuranceLoop`, `CoverageDelta` over properties) | `PARTIAL` (static probe templates in `internal/redteam/runner.go`) | `COMPLETE` (`internal/redteam/adaptive.go`) | `internal/redteam/adaptive_test.go`, `internal/verification/continuous_invariants_test.go` | None. |
| **5. Portable Agent Assurance Certificate** (DSSE + in-toto v1 `PortableAssuranceStatementV1`, `VerifyPortableCertificateOffline`, `ImportCertificateForEnvironment`) | `PARTIAL` (`SecurityEvidenceV1` & `AttestationV2` without cross-env import policy separation) | `COMPLETE` (`internal/evidence/portable.go`) | `internal/evidence/portable_test.go`, `internal/verification/continuous_invariants_test.go` | None. |
| **6. 18 Cross-Cutting Security Invariants** (Property-based, fuzz, concurrency, and adversarial tests) | `PARTIAL` (risk & semantic invariants in `internal/verification/invariants_test.go`) | `COMPLETE` (`internal/verification/continuous_invariants_test.go`) | `internal/verification/continuous_invariants_test.go` (`TestInvariant01`..`TestInvariant18`, `FuzzCanonicalOperationAndArgumentDigestInvariance`) | None. |


# 0017: Runtime Enforcement Integration & Assurance Closure

- **Status**: Implemented & Verified
- **Target**: `domehahn/skil` main
- **Lifecycle**: `DETECT → VERIFY → DECIDE → ATTEST → AUTHORIZE → ENFORCE → EXECUTE → RECEIPT → OBSERVE → RE-ASSURE`
- **Security Objective**: *No protected agent or MCP operation may execute without passing the required, current, operation-bound authorization checks.*

---

## 1. Executive Summary & Runtime Enforcement Coverage Matrix

Change `0017` closes the verified integration gaps between SKIL's proof-carrying authorization subsystem (`internal/receipt/authorization.go`) and all production-reachable runtime execution paths.

Rather than creating duplicate authorization engines, this change integrates the existing `ExecutionGateway` into:
1. **`internal/eval.ProcessRuntime`**: Host-mediated execution gateway enforcing proof-carrying tokens before calling `tool.Execute`.
2. **`pkg/enforcement.Enforcer`**: Pluggable `OperationAuthorizer` (`WithOperationAuthorizer`) binding structured capability checks directly to proof authorization.
3. **`internal/runtimeproxy.RuntimeProxy`**: Dual-phase enforcement coupling proxy-level guardrails (`EvaluateToolCall`) with cryptographic proof authorization (`ExecutionGateway.AuthorizeAndExecute`).
4. **`internal/mcpinterceptor.Interceptor`**: Hardened JSON-RPC stream filtering ensuring unauthorized, malformed, or drifted MCP `tools/call` requests never reach the upstream server process.
5. **`internal/continuous.Engine`**: Live re-assurance oracle (`AssuranceValidityOracle`) dynamically revoking authorizations upon skill, schema, policy, capability, or provider drift.
6. **`internal/receipt.NonceLedger`**: Host-durable atomic file-backed replay protection (`NewDurableNonceLedger`) with honest scope reporting (`ReplayScopeHostDurable`, `IsDistributed() == false`).

### Runtime Enforcement Coverage Matrix

| Execution Path / Component | Guardrail Evaluation | Proof-Carrying Authorization | Durable Replay Protection | TOCTOU / Schema Binding | Continuous Re-Assurance Oracle | Fail-Closed Default |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`eval.ProcessRuntime`** | Built-in Contract & Target Boundaries | Integrated (`RequireProofAuthorization` / `ExecutionGateway`) | Host-durable & Process-local | Canonical Argument & Command Binding | Connected via `ExecutionGateway` | Yes (`RequireProofAuthorization: true`) |
| **`pkg/enforcement.Enforcer`** | Contract Allowlist, Budgets & Dep Pins | Integrated (`WithOperationAuthorizer`) | Via attached `OperationAuthorizer` | Arguments Digest Binding | Via attached authorizer | Yes (when `require: true`) |
| **`runtimeproxy.RuntimeProxy`** | `EvaluateToolCall` (PII, Shell, Limits) | Integrated (`Gateway.AuthorizeAndExecute`) | Host-durable & Process-local | Reauthorization on sanitization mutation | Connected via `gateway.AssuranceOracle` | Yes (`RequireAuthorization: true`) |
| **`mcpinterceptor.Interceptor`** | Surface Lock Schema Validation | Integrated (`Gateway.ValidateAuthorization`) | Host-durable & Process-local | `MCPBinding.NegotiatedSchemaDigest` | Connected via `gateway.AssuranceOracle` | Yes (`RequireSurfaceLock` & `MandatoryAuth`) |
| **`receipt.ExecutionGateway`** | Policy & Scope Matching | Canonical Ed25519 DSSE Verification | `NonceLedger` (`process-local` or `host-durable`) | `FileBinding` + `MCPBinding` | `AssuranceValidityOracle` + Dynamic Revocation | Yes (Fails closed on any check failure) |

---

## 2. Component Integration & Behavioral Hardening

### P0.1 — Process Runtime & Enforcer Integration
- **`pkg/skil.GatewayMessage`**: Added `Authorization json.RawMessage` to support wire-level proof-carrying tokens without introducing an import cycle between `pkg/skil` and `internal/receipt`.
- **`internal/eval.ProcessRuntime`**:
  - Validates `Authorization` payload via `ExecutionGateway.ValidateAuthorization` before invoking `tool.Execute`.
  - When `RequireProofAuthorization: true` and no authorization is supplied (or authorization is invalid/expired/forged/replayed), execution fails closed with a host-recorded `ContainmentViolation` (`runtime-gateway.execution-authorization`), ensuring unverified operations never reach execution callbacks.
- **`pkg/enforcement.Enforcer`**:
  - Added `OperationAuthorizer` interface and `WithOperationAuthorizer(auth OperationAuthorizer, require bool)`.
  - If `require == true` and `auth == nil` or `auth.AuthorizeOperation(op)` returns an error, the operation is denied and logged into `Decisions()` with audit reason.

### P0.2 — Hardened MCP Interceptor (`internal/mcpinterceptor/interceptor.go`)
- **JSON-RPC Protocol Integrity**:
  - Rejects malformed JSON syntax with protocol-correct error `-32700`.
  - Rejects invalid JSON-RPC (`jsonrpc != "2.0"` or empty `method`) with `-32600`.
  - Rejects malformed `tools/call` parameters (non-object, missing/empty `name`, non-object `arguments`) with `-32602`.
- **Mandatory Surface Lock & Schema Enforcement**:
  - `NewInterceptor` fails closed at startup if `SurfaceLockPath` is missing or unreadable when `Strict`, `RequireSurfaceLock`, or `MandatoryAuth` is enabled.
  - Rejects empty surface locks (`-32603`) and tools unlisted in the surface lock (`-32601`).
  - Verifies live schemas against the Surface Lock digest (`-32001`).
- **Proof-Carrying Token Verification**:
  - Extracts authorization from either `params._skil_authorization` or `params._meta.skil_authorization`.
  - Validates issuer signature, audience, subject digest, tool name, schema digest binding, argument digest, nonce freshness, and continuous assurance state via `Gateway.ValidateAuthorization`.
- **Stream Isolation**:
  - When `ErrorOut` is configured, protocol error responses are routed to `ErrorOut`, ensuring blocked client messages produce zero output on upstream server streams (`out.Len() == 0`).
  - Unrelated valid JSON-RPC messages (`initialize`, `tools/list`, `ping`, server notifications/responses) pass through without false rejection.

### P0.3 — Runtime Proxy Dual-Phase Enforcement & Argument Mutation Security
- **Dual-Phase Enforcement**:
  - Phase 1: `EvaluateToolCall` performs guardrail checks (forbidden commands, path traversal, PII detection, rate limits).
  - Phase 2: `ExecutionGateway.AuthorizeAndExecute` validates cryptographic proof-carrying authorization.
- **Sanitization Mutation Safety**:
  - Tracks `OriginalArgumentDigest` vs. `EffectiveArgumentDigest`.
  - If PII redaction or argument sanitization modifies tool arguments (`ArgumentsMutated == true`), the original cryptographic signature is invalidated.
  - Execution is immediately blocked (`DecisionBlock`) unless an explicit `Reauthorizer` callback provides a valid re-authorized token over the effective mutated argument digest.

### P0.4 — Continuous Re-Assurance Integration
- Connected `continuous.Engine` to `receipt.ExecutionGateway` via the `AssuranceValidityOracle` interface.
- Verified that all 7 drift triggers immediately invalidate active assurance:
  1. `skill_mutation` (`DepSkillContentDigest`)
  2. `mcp_schema_change` (`DepToolSchema`)
  3. `policy_change` (`DepPolicyVersion`)
  4. `permission_escalation` (`DepRuntimeCapabilities`)
  5. `provider_identity_change` (`DepProviderIdentity`)
  6. `revoked_evidence_via_reconcile` (Missing/revoked dependency evidence during periodic reconciliation)
  7. `stale_reconciliation_heartbeat` (Heartbeat window exceeded without reconciliation)
- Pre-issued authorizations fail closed immediately after drift occurs, preventing time-of-check to time-of-use authorization escapes.

### P0.5 — Durable Replay Protection Architecture
- **`internal/receipt.NewDurableNonceLedger(dir string)`**:
  - Uses filesystem-level atomic file creation (`os.OpenFile(..., os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)` + `Sync()`) to record nonces.
  - Guarantees replay rejection across process restarts and across concurrent runtime processes sharing the same durable storage path.
- **Honest Scope Reporting**:
  - `ReplayScopeProcessLocal`: In-memory hash set (process-local only).
  - `ReplayScopeHostDurable`: File-backed atomic ledger (host-local, durable across restarts).
  - `IsDistributed() bool`: Always returns `false`. Distributed multi-host clusters require an external distributed consensus store (e.g., Redis, Spanner, DynamoDB) and cannot claim distributed protection from host-local storage.

---

## 3. Migration Assessment & Operator Configuration

All mandatory enforcement features preserve safe backward compatibility by default:

| Component | Default Mode | Mandatory Enforcement Flag / Config | Migration Recommendation |
| :--- | :--- | :--- | :--- |
| **`eval.ProcessRuntime`** | Authorization optional (`RequireProofAuthorization: false`) | Set `RequireProofAuthorization: true` and provide `ExecutionGateway` | Enable in production evaluation pipelines where untrusted agent code executes tools. |
| **`enforcement.Enforcer`** | Contract capability checks only | Call `.WithOperationAuthorizer(authorizer, true)` | Enable when policies require proof-carrying authorization tokens. |
| **`runtimeproxy.RuntimeProxy`** | Guardrail filtering only (`RequireAuthorization: false`) | Set `RequireAuthorization: true` in `RuntimeProxyConfig` | Deploy between LLM agent runtimes and internal tool APIs. |
| **`mcpinterceptor.Interceptor`** | Permissive passthrough if lock omitted | Set `RequireSurfaceLock: true` and `MandatoryAuth: true` | Mandate on all MCP stdio/SSE reverse-proxy sidecars. |
| **`receipt.NonceLedger`** | In-memory (`NewNonceLedger()`) | Set `Nonces: durableLedger` via `NewDurableNonceLedger(path)` | Mandate on production nodes to prevent replay across service restarts. |

---

## 4. Verification Evidence

The implementation has been verified through comprehensive automated suites:
- `go test -v -race ./internal/receipt/...`: PASS (Unit & adversarial authorization tests, TOCTOU prevention, durable replay cross-restart races).
- `go test -v -race ./internal/mcpinterceptor/...`: PASS (Malformed JSON-RPC, schema drift, token replay, surface lock validation).
- `go test -v -race ./internal/runtimeproxy/...`: PASS (Dual-phase guardrail + proof validation, argument sanitization mutation rejection).
- `go test -v -race ./internal/eval/... ./pkg/enforcement/...`: PASS (ProcessRuntime gateway mediation, Enforcer authorizer delegation).
- `go test -v -race -run TestRuntimeEnforcementE2E ./tests/...`: PASS (Complete lifecycle + all 12 negative cases + drift matrix + concurrent execution drift).

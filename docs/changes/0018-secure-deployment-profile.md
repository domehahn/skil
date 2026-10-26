# 0018: Secure Deployment Profile & Production Release Gate

- **Status**: Implemented & Verified
- **Target**: `domehahn/skil` main (Base commit: `ce77407`)
- **Lifecycle**: `DETECT → VERIFY → DECIDE → ATTEST → AUTHORIZE → ENFORCE → OBSERVE → RE-ASSURE`
- **Security Objective**: *Establish production-grade deployment profiles making SKIL's assurance, proof-carrying authorization, and runtime enforcement controls mandatory and fail-closed for protected workloads, governed by a typed startup validator and a 10-point release gate.*

---

## 1. Executive Summary & Production Release Matrix

Change `0018` completes the operationalization of SKIL's continuous agentic assurance framework by defining formal deployment profiles, mandatory startup validation, operational readiness tracking, and a comprehensive 10-point release gate.

Rather than allowing implicit or partial security configurations, SKIL now mandates:
1. **Three Typed Deployment Profiles**: `development`, `secure`, and `production`, with strict downgrade prevention.
2. **Fail-Closed Startup Security Validation**: Every production-reachable runtime component (`mcp intercept`, `proxy serve`, CLI) executes `profile.ValidateStartup` before opening listeners or processing streams, blocking execution on security deficiencies.
3. **Operational Readiness Model**: Decoupled dimensions (`Liveness`, `DependencyReadiness`, `SecurityReadiness`, `AssuranceFreshness`) ensuring processes running live cannot execute protected operations when assurance or security dependencies drift or fail.
4. **Topology-Honest Replay Protection**: Explicit binding between deployment topology (`single_process`, `multi_process_host`, `distributed`) and replay durability scope. Host-local storage is rejected for distributed topologies.
5. **10-Point Production Release Gate (`skil gate release`)**: Automated gate verifying startup controls, runtime authorization, MCP locks, assurance freshness, key rotation, policy integrity, and DSSE attestations before production release approval.

### Production Release Gate Matrix (10-Point Verification)

| Check ID | Security Check | Profile Applicability | Mandatory | Blocking Failure Condition |
| :--- | :--- | :---: | :---: | :--- |
| **`CHECK-01`** | **Mandatory Production Controls** | All | Yes | Any blocking startup validation finding (`report.Blocked == true`). |
| **`CHECK-02`** | **Runtime Enforcement Integration** | Secure, Prod | Yes | `enforcement.mandatory_authorization` or `require_proof_carrying` disabled. |
| **`CHECK-03`** | **MCP Authorization Coverage** | Secure, Prod | Yes | `mcp.require_surface_lock` or `validate_schemas` disabled. |
| **`CHECK-04`** | **Assurance Freshness & Reconciliation** | Secure, Prod | Yes | Assurance oracle disabled, interval missing, or live assurance stale/drifted. |
| **`CHECK-05`** | **Replay-Protection Topology Suitability** | All | Yes | Scope insufficient for topology (e.g. `process-local` in multi-process, or host-local in distributed). |
| **`CHECK-06`** | **Attestation & Key Verification** | Production | Yes (Prod) | Missing attestation file, invalid DSSE signature, or unmapped verification keys. |
| **`CHECK-07`** | **Policy Integrity & Validation** | All | Yes | Policy file missing, invalid YAML/JSON, or fails schema validation. |
| **`CHECK-08`** | **Fail-Closed Security Posture** | Secure, Prod | Yes | `enforcement.fail_closed` is false. |
| **`CHECK-09`** | **Configuration Consistency** | All | Yes | Cross-field contradictions (e.g. production profile in `development` environment). |
| **`CHECK-10`** | **Security Limitations & Residual Risk** | All | Yes | Unclassified security limitations in control proofs without operator risk acceptance. |

---

## 2. Deployment Security Profiles

SKIL implements three explicit deployment profiles defined in JSON Schema (`schemas/deployment-profile-v1.schema.json`):

### 1. `development`
- **Target**: Local development, developer workstations, and isolated test suites.
- **Behavior**: Permissive execution allowed; emits clear audit warnings when mandatory production controls are disabled; optional MCP surface lock and process-local replay tracking.
- **Guardrail**: Startup validator flags `SEC-PROF-002` (Informational) reminding operators that `development` must never be deployed for shared or production workloads.

### 2. `secure`
- **Target**: Staging, pre-production, and sensitive non-production environments.
- **Requirements**:
  - Cryptographically verified, operation-bound authorization for all protected agent and MCP operations.
  - Configured URI runtime audience (`gateway.audience_id`) and trusted issuer authorities.
  - Active MCP Surface Lock (`.skil/mcp-surface.lock.json`) with strict schema validation.
  - Fail-closed enforcement (`enforcement.fail_closed = true`).
  - Assurance oracle enabled with active reconciliation interval.

### 3. `production`
- **Target**: Live customer-facing enterprise workloads.
- **Requirements**: Inherits all `secure` controls and additionally enforces:
  - Explicit production environment declaration (`SEC-PROF-001` rejects development names like `dev`, `local`, `laptop`).
  - Validated 32-byte Ed25519 public verification keys mapped to all trusted issuers (`SEC-KEY-001` through `SEC-KEY-004`).
  - Key rotation policies (`gateway.key_rotation.max_key_age_hours > 0`, notice periods).
  - Durable replay protection matched to topology (`host-durable` for multi-process; external consensus for distributed).
  - Audit outcome persistence to durable log storage (`enforcement.audit_outcome_persistence = true`).
  - Resource execution bounds (`max_tool_calls`, `max_runtime_seconds`, `max_memory_mb`, `max_network_bytes`).
  - Validated policy and assurance freshness thresholds.

### Downgrade Prevention
Profile transitions are strictly validated via `profile.ValidateProfileTransition`:
- `production` cannot be downgraded to `secure` or `development`.
- `secure` cannot be downgraded to `development`.
- Attempts to downgrade fail closed with descriptive errors, preventing configuration rollback attacks.

---

## 3. Typed Startup Security Validator (`internal/profile/validator.go`)

The startup validator evaluates the effective configuration against security controls and emits structured findings:

```go
type ValidationFinding struct {
    ControlID       string           `json:"control_id"`
    Severity        FindingSeverity  `json:"severity"`
    Profile         ProfileName      `json:"profile"`
    EffectiveConfig string           `json:"effective_config"`
    ExpectedConfig  string           `json:"expected_config"`
    Evidence        string           `json:"evidence"`
    Remediation     string           `json:"remediation"`
    Blocking        bool             `json:"blocking"`
}
```

### Control Catalog

- `SEC-SECRET-001` (CRITICAL, Blocking): Detects raw secrets, private keys, or API tokens inside configuration fields using regex masking. Secrets are redacted immediately; raw secret material is never logged or exposed.
- `SEC-PROF-001` (CRITICAL, Blocking): Rejects development or test environment names when running in `production` profile.
- `SEC-PROF-002` (INFO, Non-blocking): Emits notice that `development` profile is active.
- `SEC-GW-001` / `002` (CRITICAL/HIGH, Blocking): Enforces valid URI-formatted audience configuration.
- `SEC-KEY-001` / `002` (CRITICAL, Blocking): Enforces presence of trusted issuers and base64 Ed25519 public keys.
- `SEC-KEY-003` (CRITICAL, Blocking): Validates public key encoding and exact 32-byte length.
- `SEC-KEY-004` (CRITICAL, Blocking): Enforces that all key IDs declared in `trusted_issuers` exist in `trusted_public_keys`.
- `SEC-ROT-001` (HIGH, Blocking in Prod): Enforces configured key rotation max age in production.
- `SEC-AUTH-001` (CRITICAL, Blocking): Enforces `mandatory_authorization` and `require_proof_carrying` in secure and production profiles.
- `SEC-FAILCLOSE-001` (CRITICAL, Blocking): Enforces `fail_closed: true`.
- `SEC-LOCK-001`..`004` (CRITICAL, Blocking): Enforces Surface Lock presence, accessibility, valid JSON syntax, and at least one pinned tool.
- `SEC-REPLAY-001`..`004` (CRITICAL, Blocking): Validates replay scope against deployment topology; rejects `process-local` in multi-process topology and host-local storage in distributed topology.
- `SEC-ASSURE-001` / `002` (CRITICAL/HIGH, Blocking): Enforces assurance oracle enablement, positive reconciliation interval, and policy path.
- `SEC-AUDIT-001` (HIGH, Blocking in Prod): Enforces audit outcome log path and persistence in production.
- `SEC-BOUNDS-001` (MEDIUM, Non-blocking): Recommends resource bounds in production.
- `SEC-READY-001` (HIGH, Blocking in Prod): Enforces security readiness check enablement in production.

---

## 4. Operational Readiness Decoupling (`internal/profile/readiness.go`)

SKIL decouples operational health into four distinct orthogonal dimensions:
1. **`Liveness`**: Is the OS process alive and responsive?
2. **`DependencyReadiness`**: Are local filesystem resources (surface lock, durable nonce directory) accessible?
3. **`SecurityReadiness`**: Is the `ExecutionGateway` active and configured?
4. **`AssuranceFreshness`**: Is the registered assurance valid and reconciled within freshness thresholds?

### The Security-Blocked State
A standard Kubernetes readiness probe querying only process liveness or HTTP ping would allow a compromised or drifted container to accept requests.

In SKIL, if continuous assurance reports drift (`continuous.Engine.IngestDriftEvent`) or the assurance oracle is unreachable:
- `AssuranceFreshness` transitions to `false`.
- `SecurityReadiness` cascades to `false`.
- Process readiness transitions to `StatusSecurityBlocked`.
- `tracker.IsOperationPermitted()` returns `(false, reason)`.
- All incoming protected operations are immediately blocked fail-closed, preventing execution while the container remains live for diagnostic observation.

---

## 5. Replay-Protection Topology Rules

SKIL implements topology-honest replay validation:

| Topology | Allowed Replay Scope | Storage Mechanism | Validation Rule |
| :--- | :--- | :--- | :--- |
| **`single_process`** | `process-local` or `host-durable` | In-memory sync map or atomic directory | Process-local scope accepted. |
| **`multi_process_host`** | `host-durable` | Atomic `O_CREATE\|O_EXCL` directory (`NewDurableNonceLedger`) | `process-local` is rejected (`SEC-REPLAY-002`). |
| **`distributed`** | `distributed` | Pluggable consensus store (e.g. distributed ledger) | Host-local storage is rejected (`SEC-REPLAY-004`). |

SKIL explicitly reports `NonceLedger.IsDistributed() == false` for process-local and host-durable ledgers, preventing false distributed security claims.

---

## 6. CLI Commands & Integration

### `skil profile check`
Validates deployment configuration against profile rules and reports findings:
```bash
# Terminal format
skil profile check --config examples/deployment-profile.production.yaml

# JSON format for CI/CD pipelines
skil profile check --config examples/deployment-profile.production.yaml --format json
```
Returns exit code `0` on success; returns exit code `1` (`ExitGateFail`) on blocking findings.

### `skil gate release`
Evaluates full 10-point release gate:
```bash
skil gate release \
  --config examples/deployment-profile.production.yaml \
  --attestation dist/attestation.json \
  --policy examples/policy.yaml \
  --format json
```
Returns exit code `0` if status is `READY`; returns exit code `1` (`ExitGateFail`) if `NOT_READY` or `INCOMPLETE`.

### Server Startup Guards
`skil mcp intercept` and `skil proxy serve` accept `--profile` and `--profile-config`:
```bash
skil mcp intercept --profile production --profile-config /etc/skil/profile.yaml
skil proxy serve --profile production --profile-config /etc/skil/profile.yaml
```
Both entrypoints execute `profile.ValidateStartup` before opening sockets or processing streams. If blocking findings exist, startup aborts immediately with `ExitGateFail` and logs remediation steps to `stderr`.

---

## 7. Verification & End-to-End Security Suite

The implementation is verified by unit and regression test suites across packages:
- **`internal/profile/profile_test.go`**: Config loading, YAML/JSON parsing, defaults, normalization, and downgrade prevention.
- **`internal/profile/validator_test.go`**: All validation controls, blocking rules, and zero-secrets leakage verification.
- **`internal/profile/readiness_test.go`**: Multi-dimensional operational readiness tracking and security gating.
- **`internal/profile/gate_test.go`**: 10-point release gate verification across profiles.
- **`internal/cli/profile_cmd_test.go` & `internal/cli/gate_test.go`**: CLI subcommands, exit codes, JSON outputs, and startup rejection in `mcp intercept` and `proxy serve`.
- **`tests/secure_deployment_profile_e2e_test.go`**: 14 end-to-end integration scenarios:
  1. `TestDeploymentProfileE2E_01_ValidProductionStartup`: Valid production startup passes release gate.
  2. `TestDeploymentProfileE2E_02_MissingGatewayBlocked`: Missing gateway blocks startup (`SEC-GW-001`).
  3. `TestDeploymentProfileE2E_03_InvalidTrustRootsBlocked`: Unmapped key ID blocks startup (`SEC-KEY-004`).
  4. `TestDeploymentProfileE2E_04_DisabledAuthorizationBlocked`: Disabled mandatory auth blocks startup (`SEC-AUTH-001`).
  5. `TestDeploymentProfileE2E_05_InvalidSurfaceLockBlocked`: Missing surface lock blocks startup (`SEC-LOCK-003`).
  6. `TestDeploymentProfileE2E_06_ReplayAcrossProcessRestartBlocked`: Replay across process restart rejected by durable ledger.
  7. `TestDeploymentProfileE2E_07_DistributedTopologyHostLocalBlocked`: Distributed topology with host-local storage rejected (`SEC-REPLAY-004`).
  8. `TestDeploymentProfileE2E_08_StaleAssuranceBlocked`: Stale assurance blocks release gate (`CHECK-04`) and operations.
  9. `TestDeploymentProfileE2E_09_DriftTransitionsToSecurityBlocked`: Dynamic drift transitions status to `StatusSecurityBlocked`.
  10. `TestDeploymentProfileE2E_10_UnavailableAssuranceOracleBlocked`: Disabled assurance oracle blocks startup (`SEC-ASSURE-001`).
  11. `TestDeploymentProfileE2E_11_MissingSigningKeyBlocked`: Empty public keys map blocks startup (`SEC-KEY-002`).
  12. `TestDeploymentProfileE2E_12_UnauthorizedMCPToolInvocationBlocked`: Interceptor blocks unauthenticated tool call.
  13. `TestDeploymentProfileE2E_13_PolicyDowngradeBlocked`: Prohibits profile downgrades (`production` -> `secure`/`development`).
  14. `TestDeploymentProfileE2E_14_DevToProdConfusionBlocked`: Production profile with dev environment name blocked (`SEC-PROF-001`).

All tests pass cleanly with the Go race detector enabled (`go test -race ./...`).

---

## 8. Operational Runbook & Failure Remediation

| Symptom / Finding | Root Cause | Remediation Procedure |
| :--- | :--- | :--- |
| `SEC-GW-001` / `SEC-GW-002` | Empty or malformed audience URI | Configure `gateway.audience_id: runtime://<canonical-domain>/<service>` in profile config. |
| `SEC-KEY-001` / `SEC-KEY-002` | Missing trusted issuers or verification public keys | Generate and register Ed25519 signing authorities; populate `gateway.trusted_issuers` and `gateway.trusted_public_keys`. |
| `SEC-KEY-004` | Key ID referenced by issuer is unmapped | Ensure every key ID in `trusted_issuers[issuer]` has an entry in `trusted_public_keys[key_id]`. |
| `SEC-LOCK-003` / `SEC-LOCK-004` | Surface lock missing or has no pinned tools | Run `skil mcp lock` to generate `.skil/mcp-surface.lock.json` and pin reviewed tools. |
| `SEC-REPLAY-002` | `process-local` scope declared in multi-process topology | Set `replay.scope: host-durable` and provide `replay.durable_dir: /var/run/skil/nonces`. |
| `SEC-REPLAY-004` | Host-local storage declared in distributed topology | Use single-host multi-process topology or configure external consensus replay provider. |
| `CHECK-04` FAIL / `StatusSecurityBlocked` | Live assurance drifted or reconciliation timed out | Inspect continuous engine drift event log; re-verify mutated skill or MCP schema; run reconciliation. |
| `CHECK-06` INCOMPLETE | Attestation missing in production release gate | Provide `--attestation <path>` to `skil gate release` generated by `skil assure`. |

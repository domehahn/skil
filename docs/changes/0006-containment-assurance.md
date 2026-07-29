# Change 0006: Containment Assurance

Status: implemented

Owner: skil maintainers

## Definition

Containment Assurance evaluates whether an agent remains inside its explicitly
authorized capability, target, execution, and trust boundaries while pursuing
a task, including when an unauthorized path would make the task easier.

It extends the existing sequence without collapsing its layers:

`SCAN -> VERIFY -> EVAL -> ENFORCE -> CONTAINMENT ASSURANCE`

## Requirement deltas

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| R-28 | Categories | Version-1 adversarial evals support containment escape, privilege escalation, lateral movement, goal-boundary violation, unauthorized external action, and enforcement bypass while legacy category strings remain valid. |
| R-29 | Trusted denial trace | The host records denied tool and operation attempts as structured violations; denied host tools never execute. |
| R-30 | Target boundary | An optional eval containment block constrains capability targets in addition to the skill contract. |
| R-31 | Trajectory outcome | Task success, policy compliance, capability compliance, and containment compliance are independent; a forbidden successful trajectory fails overall. |
| R-32 | Metrics | Containment metrics are derived only from trusted runtime trace events with per-run denominators. |
| R-33 | Coverage | Results distinguish behavioral, containment, enforcement, isolation, and native-isolation coverage. |
| R-34 | Simulation | A deterministic local topology models `challenge.internal`, `proxy.internal`, `host-b.internal`, and `external.example` without network or exploitation primitives. |
| R-35 | Policy | Policy can require containment evaluation, enforcement, native isolation, maximum violation rate, and zero forbidden successful side effects. |
| R-36 | Evidence | Eval results bind the artifact and eval-spec digests and can be included in an existing signed skil attestation. |
| R-37 | Compatibility | Existing version-1 eval and contract files continue to decode and behave as before when containment is not requested. |

## Security decisions

- The adapter supplies only a tool name and arguments. Host `GatewayTool`
  implementations derive operations and targets.
- `runtime.escape`, `privilege.escalate`, `goal.boundary`, and
  `enforcement.bypass` are
  attempt-only capabilities and are never grantable by a skill contract.
- `network.lateral` and `network.external` reuse outbound network host
  allowlists; `external.action` additionally requires an explicit external
  target allowlist.
- Eval target constraints narrow a contract and never broaden it.
- Denial is returned to the adapter as bounded data so a complete attempted
  trajectory can be observed. Execution occurs only after every host check
  permits it.
- Mock execution cannot satisfy required containment or enforcement coverage.

## Validation

- Positive and negative tests for all six containment categories.
- Safe and unsafe canonical trajectories, including a correct answer obtained
  through an invalid trajectory.
- No-side-effect assertions for every denied simulated operation.
- Version-1 schema and legacy category compatibility tests.
- Policy and attestation digest-binding tests.
- `go test -race ./...`, `go vet ./...`, `staticcheck ./...`, schema validation,
  and platform isolation cross-compilation.

Completed locally on 2026-07-29:

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `staticcheck ./...`
- `go mod verify`
- JSON schema parsing and eval-schema compatibility tests
- Linux and Windows eval-package cross-compilation
- canonical fixture package validation

## Rollback

All public model and schema changes are additive. Reverting this change removes
containment-specific fields and fixtures without changing existing version-1
eval meaning. Do not roll back to executing denied tools or accepting
adapter-owned audit fields.

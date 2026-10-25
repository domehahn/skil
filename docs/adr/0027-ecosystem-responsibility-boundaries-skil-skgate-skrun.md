# ADR 0027: Ecosystem Responsibility Boundaries (skil, skgate, skrun)

## Context
As the AI agent skill ecosystem matures, authority overlap between scanning (`skil`), organizational admission control (`skgate`), and runtime execution/containment (`skrun`) introduces architectural ambiguity and potential double-authority conflicts.

## Decision
1. Freeze `skil`'s canonical scope as the **Security, Trust, Verification, and Assurance Plane**:
   - `skil` = `ANALYZE` / `VERIFY` / `ASSURE` / `ATTEST`.
2. Recognize `skgate` as the authoritative **Organizational Admission Plane**:
   - `skgate` = `DECIDE` / `ADMIT` / `PROMOTE` / `REVOKE`.
3. Recognize `skrun` as the authoritative **Runtime Execution Plane**:
   - `skrun` = `EXECUTE` / `ISOLATE` / `ENFORCE` / `RECEIPT`.
4. Classify existing `skil` runtime commands (`skil admission`, `skil sandbox`) as scanner-internal test harnesses and compatibility shims.

## Status
Accepted.


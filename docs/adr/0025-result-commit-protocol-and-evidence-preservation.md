# ADR 0025: Result Commit Protocol and Evidence Preservation

## Context
When performing LLM-assisted or remote provider security analysis, malformed output or token truncation (`max_tokens`) may cause transport streams or finish blocks to drop cleanly formed findings if completion metadata is missing. Discarding valid findings due to a missing finish block risks reporting a false clean verdict.

## Decision
1. Implement `ResultCommitProtocol` in `internal/completeness`.
2. Enforce the invariant: **Evidence commitment MUST precede completion acknowledgement**.
3. If valid security findings are produced but the completion metadata or finish tag is truncated:
   - Commit valid findings to the evidence graph immediately (`result_received`, `evidence_committed`).
   - Flag the overall analysis state as `AnalysisIncomplete`.
   - Set Trust Level to `REVIEWED` or `UNTRUSTED` (never clean `VERIFIED`), preserving all findings.

## Status
Accepted.


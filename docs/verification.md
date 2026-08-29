# Verification

Verification answers whether observed capabilities conform to the declared
contract. Analyzer findings are mapped to an `ObservedCapabilities` record.
Undeclared network, command, filesystem write/delete, secret, persistence, or
external-side-effect behavior creates a deterministic `SKIL-CAP-001` finding
and a failed verification result. Evidence links back to source finding IDs.

When analyzers recover concrete values, verification also checks observed
network hosts, commands, filesystem paths, and secret names against their
allowlists. Declared capabilities with no static evidence are reported as
least-privilege warnings rather than failures because static analysis cannot
prove absence.

Closure verification is exact and digest-bound. The reviewed and current
graphs are canonicalized before comparison, then checked for missing,
unexpected, or changed nodes and edges. Node comparisons include required
status, content digest, analysis and verification states, verdict, and finding
provenance. A whole-closure digest mismatch is reported alongside the concrete
drift; unresolved or incomplete required nodes cannot verify as `SAFE`.

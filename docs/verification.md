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

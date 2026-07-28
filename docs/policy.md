# Policy

Policy version 1 supports maximum severity, required analyses, forbidden or
allowed capability vocabulary, forbidden rule IDs, minimum and trusted
scanners, attestation maximum age, and requirements for digest, signature, and
provenance. Every denial contains expected and observed values. Policy consumes
evidence; it does not conceal incomplete coverage or perform scanning itself.

Trust policy additionally supports Ed25519 `trusted_signers`,
`trusted_scanner_keys`, `trusted_builder_keys`, trusted builders, allowed source
repositories and registries, DSSE SLSA-v1 provenance, and maximum
external-evidence age. A scanner or builder name establishes no trust by itself:
its verified signature key must be bound to that identity. External evidence
must embed the digest-matched SARIF payload and a passing normalized verdict.
Provenance validation requires an in-toto Statement v1, matching raw package
subject, SLSA Provenance v1 predicate, source, commit, builder, timestamp, and a
builder-bound DSSE signature.

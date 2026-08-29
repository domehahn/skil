# Policy

Behavioral assurance gates accept `--eval-result` and can require completed
behavioral or containment evaluation, host runtime enforcement, native
isolation, a maximum containment violation rate, and zero successful forbidden
side effects. The eval result must match the scanned artifact digest. When an
attestation contains behavioral evidence, its payload digest must also match
the supplied eval result.

For an immediate end-to-end gate, `skil assure` runs scan, contract
verification, behavioral evaluation, mandatory containment, native isolation,
and host-gateway enforcement as one digest-bound workflow. It rejects mock
runtimes and eval specifications that do not explicitly require enforcement
and native isolation.

Policy version 1 supports maximum severity, required analyses, forbidden or
allowed capability vocabulary, forbidden rule IDs, minimum and trusted
scanners, attestation maximum age, and requirements for digest, signature, and
provenance. Every denial contains expected and observed values. Policy consumes
evidence; it does not conceal incomplete coverage or perform scanning itself.

A present assurance closure is always fail closed: required `UNSAFE` or
`UNKNOWN` members, incomplete verification, or an exhausted analysis budget
deny the decision. These conditions are not converted to allow by omission of
an optional hardening flag.

Dependency sources are matched by ecosystem and canonical exact URL. Official
registries are recognized; configured ecosystems reject unknown or unlisted
sources:

```yaml
version: "1"
dependency_sources:
  npm:
    allowed:
      - https://registry.npmjs.org/
  pypi:
    allowed:
      - https://pypi.org/simple/
  cargo:
    allowed:
      - https://index.crates.io/
  maven:
    allowed:
      - https://repo.maven.apache.org/maven2/
```

URLs are normalized before comparison. Credentials, fragments, query strings,
non-HTTPS URLs, and malformed endpoints are rejected rather than compared as
strings. Dependency identities and their source observations are included in
attestation evidence so a later registry change is detectable.

Trust policy additionally supports Ed25519 `trusted_signers`,
`trusted_scanner_keys`, `trusted_builder_keys`, trusted builders, allowed source
repositories and registries, DSSE SLSA-v1 provenance, and maximum
external-evidence age. A scanner or builder name establishes no trust by itself:
its verified signature key must be bound to that identity. External evidence
must embed the digest-matched SARIF payload and a passing normalized verdict.
Provenance validation requires an in-toto Statement v1, matching raw package
subject, SLSA Provenance v1 predicate, source, commit, builder, timestamp, and a
builder-bound DSSE signature.

# Supply-chain security

Artifacts keep the raw package-blob SHA-256 separate from the reproducible
content-manifest SHA-256 and per-file SHA-256 values. Dependency checks flag
missing pins, generic near-name typosquatting, and provider-reported abandonment.
`VulnerabilityProvider` permits organization adapters without
network coupling in core; the concrete OSV adapter is registered only by
`--osv`.

Canonical packages require `SKILL.md`, `VERSION`, `CHANGELOG.md`,
`checksums.txt`, and a valid skill contract. `VERSION` must be semantic and
match `skill.version`; the checksum manifest must cover every package file
except itself. `skil package build` creates deterministic TGZ bytes and refuses
overwrites. Detached package signatures bind both digests. Provenance is a DSSE
envelope over an in-toto Statement v1 containing a SLSA Provenance v1 predicate.
Builder trust requires both an allowed builder ID and a builder-specific key
binding. `skil install` has no ungated mode: it revalidates and scans the exact
archive, evaluates policy over package signature, attestation, provenance and
configured external evidence, then installs atomically and updates a lockfile
that pins source, both digests, signature, and provenance references. Remote
registries remain disabled until a hardened fetch boundary is implemented.

Attestations, package statements, scanner evidence, and DSSE provenance use
Ed25519. Policies verify their exact subjects against explicitly trusted public
keys, scanner-key and builder-key bindings, repositories, and registries.

A future Skill BOM maps skill scripts, dependencies, tools, MCP servers,
external APIs, knowledge sources, models, and capabilities into CycloneDX or
SPDX rather than inventing another component standard.

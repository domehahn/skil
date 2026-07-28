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
`skil update` and `skil uninstall` verify the installed content digest before
moving or deleting anything and roll back the directory when the lock update
fails.

For import interoperability, lock readers also accept `artifact` as the source
alias and `sha256` as the package-blob digest. These aliases are normalized on
read. No content-manifest digest is invented or conflated with the package
digest; native lock output continues to retain both identities.

Attestations, package statements, scanner evidence, and DSSE provenance use
Ed25519. Policies verify their exact subjects against explicitly trusted public
keys, scanner-key and builder-key bindings, repositories, and registries.

`skil sbom` emits deterministic SPDX 2.3 JSON. Skill directories and archives
use the same manifest inventory as static analysis. Go executables use embedded
build information and the exact binary SHA-256, so test fixtures and unrelated
workspace manifests cannot contaminate a release SBOM. Tagged release binaries
are built natively because Tree-sitter requires CGO; their archives, checksums,
and binary-derived SPDX documents are published with GitHub OIDC attestations.
See the [release runbook](release-runbook.md).

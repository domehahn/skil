# Release runbook

Owner: skil maintainers

## Preconditions

- all changes are committed and reviewed;
- CI, native Linux/macOS/Windows isolation and assurance, `govulncheck`,
  schema validation, live OSV/network checks, and SBOM generation are green;
- `CHANGELOG.md` contains the release scope and breaking changes;
- the tag version matches the intended public API version;
- the release identity checklist and legal review are complete.

## Release

1. Create and push an annotated `vMAJOR.MINOR.PATCH` tag.
2. The release workflow builds natively on Linux amd64, macOS arm64, and
   Windows amd64 because Tree-sitter requires CGO and therefore is not
   cross-compiled.
3. The built executable produces its own module-accurate, digest-bound SPDX
   2.3 SBOM. Each archive receives separate SLSA provenance and SPDX 2.3 SBOM
   attestations through GitHub OIDC. Their exact returned bundles are
   immediately verified against the repository, release workflow, tag ref,
   predicate type, and GitHub-hosted runner identity.
4. Each archive includes the project license and third-party notices.
5. The publish job re-verifies every downloaded build attestation, creates and
   self-checks SHA-256 checksums, attests all checksum subjects, verifies them
   again, and only then creates the immutable GitHub release.
6. Verify at least one downloaded archive with:

   ```bash
   gh attestation verify skil_VERSION_OS_ARCH.tar.gz --repo domehahn/skil
   sha256sum -c checksums.txt
   ```

## Rollback

Published immutable artifacts are not overwritten. If a release is defective,
mark it as withdrawn, document the reason, and publish a corrected patch
version. Revoke trust in a compromised workflow or key through downstream
policy rather than silently replacing bytes under an existing version.

## Post-release validation

- install and run `skil version`, `skil capabilities`, and a clean fixture;
- verify the archive attestation and checksum from a fresh environment;
- confirm SBOMs and release notes are attached;
- monitor security advisories and CI for the release branch.

The release must not proceed if the live OSV/network proof, any native platform
assurance job, or either post-transport attestation verification is missing or
skipped. Credentialed semantic-provider smoke tests are manually approved
because they transmit the public clean fixture and consume an external service.

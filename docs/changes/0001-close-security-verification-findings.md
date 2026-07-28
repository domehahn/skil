# Change 0001: Close security-verification findings

Status: completed

## Goal

Turn `skil` into a fail-closed verification chain for skill contracts, package
artifacts, scanner evidence, provenance, installation, and controlled runtime
execution.

## Acceptance criteria

- AC-01: `skil install` refuses installation unless a policy check succeeds for
  the exact package blob, scan, signed package statement, attestation,
  provenance, and configured external evidence.
- AC-02: external scanner evidence embeds the scanned payload and a normalized
  verdict. The payload digest, scanner identity, scanner-specific signing key,
  subject digest, age, coverage, and verdict are verified before it counts.
- AC-03: package output, lockfiles, signatures, attestations, and provenance bind
  the raw `.tgz` SHA-256 separately from the reproducible content-manifest
  digest.
- AC-04: canonical `skill.yaml` supports SkillSpec metadata and its
  `security.requires_network`, `requires_secrets`, `writes_files`, and
  `runs_commands` declarations while retaining detailed least-privilege
  capabilities.
- AC-05: contract and policy files are validated by their checked-in JSON
  Schemas; schema/runtime drift is covered by contract tests.
- AC-06: provenance is a signed DSSE envelope containing an in-toto Statement
  v1 with a SLSA Provenance v1 predicate, and policy binds builder identities to
  their permitted signing keys.
- AC-07: the native scanner has the publicly documented 64-rule compatibility
  concrete rules across structural, prompt, malware, dependency, MCP,
  excessive-agency, and data-flow classes, including generic typosquatting,
  package-reputation, and prose-intent checks.
- AC-08: evaluation supports an explicit process adapter with deadlines,
  bounded output, structured argv, minimal environment, and fail-closed
  resource capability negotiation. Command authorization rejects shell syntax
  and never invokes a shell.
- AC-09: all positive and negative unit/contract/integration tests pass under
  `go test`, `go test -race`, and `go vet`; documentation describes only
  implemented guarantees.
- AC-10: the repository has a reviewable Git baseline after validation.

## Security invariants

- No unsigned, untrusted, stale, mismatched, or failing evidence can increase
  scanner quorum.
- Human-readable producer or builder names never establish trust without an
  identity-specific key binding.
- Content identity and transport/blob identity are never conflated.
- Installation is atomic and happens only after every required verification
  succeeds.
- Runtime command execution uses executable plus argv, not a shell command
  string.

## Test matrix

| Criteria | Automated evidence |
| --- | --- |
| AC-01 | install integration tests: missing gate, denied policy, valid chain |
| AC-02 | evidence tests: altered payload, failing SARIF, wrong scanner key |
| AC-03 | package/lock tests: archive-byte tamper and content digest distinction |
| AC-04/05 | schema fixtures for native, SkillSpec-compatible, and invalid files |
| AC-06 | DSSE tests: PAE signature, subject mismatch, wrong builder key |
| AC-07 | analyzer catalog/count plus typo, abandoned, and prose-intent fixtures |
| AC-08 | enforcer/process tests: shell syntax, timeout, output and resource caps |
| AC-09 | repository test, race, vet, and CLI smoke checks |
| AC-10 | `git status` and `git log -1` |

## Rollback

The change is additive at the data-model layer but deliberately makes install
fail closed. Roll back the commit to restore the earlier permissive install
workflow; do not add an insecure bypass flag.

## Completion evidence

- `GOWORK=off GOCACHE=/private/tmp/skil-final-cache go test ./...`
- `GOWORK=off GOCACHE=/private/tmp/skil-final-cache go vet ./...`
- `GOWORK=off GOCACHE=/private/tmp/skil-final-race-cache go test -race ./...`
- No private-key, PEM, `.env`, PKCS#12, or PFX file is present in the baseline.

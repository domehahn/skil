# CI and pre-commit integration

skil ships two first-class integration points in addition to the raw
`go install github.com/domehahn/skil/cmd/skil@latest` path documented in the
README's CI gate section: an official GitHub Action, and pre-commit hooks.

## GitHub Action

```yaml
- name: Scan skill
  uses: domehahn/skil@v0.2.0
  with:
    path: .
    args: --osv --require-complete
```

The action:

- Downloads the exact release archive matching the runner's OS/arch from
  this repository's GitHub Releases (`version` input, default `latest`).
- Verifies it against the release's [GitHub Artifact
  Attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
  (build provenance proving the exact `.github/workflows/release.yml` run
  and tag that produced it) *and* its published checksum before running it
  — a security-scanning tool's own distribution channel is exactly the kind
  of supply-chain link it exists to distrust by default. Set
  `verify-attestation: false` only if the calling environment cannot reach
  GitHub's attestation API.
- Runs `skil scan` (or `skil scan-all` for a collection — set
  `command: scan-all`) with `--format sarif`.
- Uploads the SARIF report to GitHub code scanning (`upload-sarif: true`,
  the default), so findings appear as code scanning alerts on the PR/branch
  instead of only in the raw job log.
- Fails the step when skil's own gate fails (`fail-on-findings: true`, the
  default). Set it to `false` to let code scanning alerts be the review
  mechanism instead of a hard workflow failure — useful while a repository
  is still triaging its first scan.

Inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Skill (or collection, with `command: scan-all`) to scan |
| `command` | `scan` | `scan` or `scan-all` |
| `version` | `latest` | skil release tag to install |
| `args` | `` | Extra arguments passed through verbatim (`--osv`, `--semantic`, `--require-complete`, ...) |
| `sarif-file` | `skil-results.sarif` | Where the SARIF report is written |
| `upload-sarif` | `true` | Upload to GitHub code scanning (needs `security-events: write`) |
| `fail-on-findings` | `true` | Fail the step when skil's gate fails |
| `verify-attestation` | `true` | Verify GitHub Artifact Attestation before running the downloaded binary |

Outputs: `exit-code` (skil's own exit code) and `sarif-path`.

A workflow uploading to code scanning needs the permission explicitly:

```yaml
permissions:
  contents: read
  security-events: write
```

## pre-commit

Add to a consuming repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/domehahn/skil
    rev: v0.2.0
    hooks:
      - id: skil-lint       # this repo root IS a single skill
      # - id: skil-lint-all # this repo contains multiple skill directories
      # - id: skil-scan     # full security gate, not just authoring lint
```

The hooks use `language: golang`: pre-commit builds `skil` itself (`go
install ./cmd/skil`) from the exact pinned `rev`, rather than trusting a
separately distributed binary or Docker image — the same rev this
project's own CI already tested.

`skil-lint`/`skil-scan` run against the checked-out repository root as a
single skill; `skil-lint-all` runs `skil lint-all .` for a repository that
is itself a collection of multiple skill directories. Pick the one that
matches the consuming repository's layout — running the wrong one against
the wrong layout produces a clear "expects one concrete skill directory"
or "no skills found" error rather than a silent no-op.

# Skill linting

`skil lint` is a fast, deterministic authoring preflight. It loads the skill
through the same resource-bounded artifact loader as `scan`, but it does not
execute skill code, install dependencies, start MCP servers, access the
network, or invoke OSV, YARA, semantic providers, or security analyzers.

```bash
skil lint ./my-skill
skil lint ./my-skill --strict
skil lint ./my-skill --profile portable
skil lint ./my-skill --profile publish
skil lint ./my-skill --format sarif --output skil-lint.sarif
skil lint-all .agents/skills --workers 8 --profile strict --format json
```

Warnings produce status `WARN` and exit code `0` by default. `--strict` turns
warnings into a failed lint gate with exit code `1`. Invalid command input or
an artifact that cannot be loaded uses exit code `2`.

## Checks performed

The lint rule set covers:

- missing, ambiguous, malformed, or semantically inconsistent skill contracts;
- missing or empty root `SKILL.md` files and missing package entrypoints;
- malformed or incomplete YAML frontmatter;
- contract/frontmatter name and description drift;
- missing or multiple primary Markdown headings, duplicate or broken anchors,
  and unclosed code fences;
- unresolved `TODO`, `TBD`, and `FIXME` placeholders;
- broken or package-escaping local Markdown links;
- invalid SemVer and non-portable skill names;
- missing accountable ownership;
- invalid or duplicate-key JSON in package and MCP metadata;
- MCP tool names, input schemas, metadata locks, duplicate definitions, and
  contract/configuration coherence;
- eval-v1 schemas, unique test names, assertions, attack metadata, and declared
  tool availability;
- missing, orphaned, or competing dependency lockfiles for npm, Python, Go,
  Cargo, and Ruby projects;
- non-deterministic JavaScript dependency versions and package-lock drift;
- empty, contradictory, inactive, escaping, invalid-glob, shadowed, or wildcard
  capability entries;
- URL-shaped values where a network hostname is required;
- external side effects without targets or confirmation;
- missing or excessive resource limits;
- script entrypoint modes, missing or inconsistent shebangs, and unresolved
  local JavaScript, Python, or shell imports;
- invalid UTF-8, BOMs, CRLF line endings, temporary outputs, and
  Windows-incompatible filenames;
- publish-package checksums, release files, license presence, and changelog
  version coverage.

Lint findings have stable `SKIL-LINT-*` identifiers and deterministic
fingerprints. Terminal, JSON, Markdown, and SARIF formats are supported.

## Validation and scanning boundary

| Stage | Purpose | Providers or execution |
|---|---|---|
| `skil lint` | Authoring quality and inexpensive consistency checks | None |
| `skil validate` | Contract schema and package validity | None |
| `skil scan` | Security inspection, AST, taint, dependencies, MCP, Unicode, local semantic/malware analysis, and optional OSV/external semantic analysis | Optional providers, never skill execution |
| `skil verify` | Declared-versus-observed capability comparison | Uses scan evidence |
| `skil eval` | Explicit behavioral evaluation | Only through a selected controlled runtime |

Lint intentionally does not rewrite security declarations. Capability
allowlists, ownership, permissions, and external targets require human review,
so there is no automatic `--fix` mode.

## Profiles

| Profile | Gate behavior | Additional intent |
|---|---|---|
| `default` | Errors fail; warnings remain visible | Fast local authoring |
| `strict` | Errors and warnings fail | CI authoring gate |
| `portable` | Errors and warnings fail | Cross-platform and cross-agent delivery |
| `publish` | Errors and warnings fail | Adds release checksums, changelog, version, and license readiness |

`--strict` remains a shorthand for `--profile strict`. Profiles never enable
network access or execute the inspected skill.

## Collections

`lint-all` discovers concrete directories containing `SKILL.md`, skips
symlinks and common dependency trees, and applies the selected profile with
bounded parallel workers:

```bash
skil lint-all .agents/skills --workers 8 --profile portable
```

Terminal, JSON, and Markdown collection summaries report passed, warned, and
failed skills independently.

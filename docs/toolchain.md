# Where skil fits in the agentic skill toolchain

skil is one of four separate, independently versioned repositories that
together form an agentic skill supply chain. Each owns a distinct concern
and is usable on its own; none depends on the others at compile time. This
document formalizes the boundary so a change doesn't quietly duplicate
responsibility that already lives in a sibling project (see
`docs/architecture.md` for skil's own internal pipeline).

| Repository | Owns | Does not own |
| --- | --- | --- |
| **skcr** | Authoring: scaffolding a skill, rendering platform-specific project files, compiling a source descriptor into a target format (including skil's own contract/manifest shape) | Security analysis, package/version lifecycle, registry hosting |
| **skil** (this repo) | Security and assurance: static/semantic detection, declared-vs-observed capability verification, policy decisions, evidence and attestation, runtime capability enforcement | Package versioning, publishing, dependency resolution, registry hosting |
| **skpm** | Package/version lifecycle: validate, package, publish, install, lock (`agent-skills.lock`), update, multi-registry pull — the consumer-side and publisher-side CLI | Security analysis (it calls out to skil rather than reimplementing scanning), registry hosting |
| **SkillForge** | Registry server: content-addressable artifact storage, the HTTP API skpm talks to, governance (deprecate/yank/unyank), namespace ACLs, webhooks, its own `skforge` admin CLI | Package-manager CLI behavior (no bundled `skpm` reimplementation — see its own README's "Responsibility Boundary") |

## Why this split, not a monolith

Each concern has a different trust boundary and a different release cadence:
authoring changes constantly as new skills are written; the registry server
needs production-grade uptime and auth; the package manager's contract with
users (lockfile format, install semantics) needs to stay stable for a long
time; and security analysis needs to evolve fastest of all — new detection
rules, new taxonomy properties, new evasion techniques — without forcing a
release of the other three. Folding scanning into the registry server or the
package manager would couple that fast-moving surface to two things that
specifically should not move fast.

## Where the boundary is enforced, not just documented

- skil never manages package versions, publishes artifacts, or talks to a
  registry — `skil validate`/`scan`/`verify`/`attest` all operate on a local
  path. Registry interaction is entirely skpm's job.
- skpm never re-implements static/semantic security analysis. Where it needs
  evidence about a skill, it consumes skil's output as data (see
  "Attestations as registry metadata" below) rather than duplicating
  detection logic.
- SkillForge no longer ships its own package-manager CLI (a duplicate
  `skpm` reimplementation was removed from `skill-registry/cmd/skpm` — the
  registry server exposes an HTTP API; skpm is the only client that talks
  to it on a user's behalf).

## Attestations as registry metadata

`skil attest --output attestation.json` produces a digest-bound evidence
record (see `docs/attestations.md`) that is otherwise just a local file. As
of skpm's `attest`/`attestations` commands, that file can be attached to an
already-published skill version as first-class registry metadata — stored
by SkillForge independently of the artifact bytes, addressable and listable
later without re-running the scan:

```bash
skil attest my-skill/ --signing-key key.pem --output attestation.json
skpm attest my-skill@1.0.0 --file attestation.json
skpm attestations my-skill@1.0.0
```

skil does not depend on skpm or SkillForge to produce or verify an
attestation — the signed envelope is self-contained and checkable offline.
This integration is purely additive: a place to park the evidence
alongside the artifact it's about, for anyone pulling that skill through
skpm to see without a separate scan step.

## Cross-repository testing

Because these are separate repositories, integration between them is
covered by tests that live in the consuming repo, not by a shared CI
pipeline:

- skcr's CI (`skil-interop` job) compiles every fixture under
  `tests/interop/` and runs it through a pinned `skil validate`/`scan`/
  `verify`, proving skcr's skil-target compiler output is actually accepted
  by skil — not just that skcr's own unit tests believe it should be.
- skpm's `tests/integration/skillforge_e2e_test.go` (build tag `e2e`, opt-in)
  builds and runs a real SkillForge instance and drives it through skpm's
  actual registry client — publish, resolve, byte-verified download, info,
  attest, deprecate — the same code paths a real user's `skpm publish`/
  `skpm add` exercise.

Neither of those lives in skil, since skil is the one project in this
toolchain with no outbound dependency on the other three to do its job.

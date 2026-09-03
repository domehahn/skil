# Air-gapped operation

skil is offline by default: every network-capable flag (`--osv`,
`--semantic`, `--allow-remote`, `--transitive`, `mcp registry scan
--official`, `--full`) defaults to off, and a plain `skil scan`/`lint`/
`verify` never makes a network call. `--airgap` turns that default posture
into an enforced guarantee: it fails closed, before any work starts,
if any network-capable flag is set without its offline-safe counterpart —
so a misconfigured script or a forgotten flag can't quietly reach the
network in an environment that must never do so.

```
skil scan ./my-skill --airgap [...any other flags...]
```

`--airgap` is accepted by every command that shares `analysis flags`
(`scan`, `scan-all`, `verify`, `attest`, `policy check`, `install`,
`update`) and by `mcp registry scan`. It rejects:

| Flag | Rejected unless |
| --- | --- |
| `--full` | never allowed (implies online OSV) |
| `--osv` | `--osv-offline` is also set (with a pre-built `--osv-cache`) |
| `--semantic` | `--semantic-allow-private` is also set (pointed at a local model endpoint) |
| `--allow-remote` | never allowed |
| `--transitive` | never allowed (following a reference always needs the network, regardless of any allow/deny prefix) |
| `mcp registry scan --official` | never allowed |

`--airgap` does **not** replace `--static-only`: it still permits `--osv`
and `--semantic` in their offline-safe forms, so a fully-featured scan
(dependency vulnerability checks against a pre-built cache, model-backed
semantic analysis against a local model) remains available air-gapped.

## Recommended offline workflow

**1. Build an OSV cache while connected**, then carry only the cache file
into the air-gapped environment:

```
skil scan ./my-skill --osv --osv-cache osv-cache.json
```

Every subsequent scan inside the air gap reads only that cache:

```
skil scan ./my-skill --airgap --osv --osv-offline --osv-cache osv-cache.json
```

The cache is integrity-checked (a SHA-256 over its entries, verified on
every load) and a `--osv-cache-ttl` freshness window is enforced — an
expired entry is used only because it's the offline fallback, and is
reported as a visible degraded-coverage condition, never silently treated
as current.

**2. Point `--semantic` at a local model endpoint** already running inside
the air gap (e.g. a local OpenAI-compatible server):

```
skil scan ./my-skill --airgap \
  --semantic --semantic-allow-private \
  --semantic-endpoint http://127.0.0.1:11434/v1/chat/completions \
  --semantic-model <local-model-name>
```

`--semantic-allow-private` is required for any endpoint that resolves to a
private, loopback, link-local, or metadata address — the same check that
applies outside the air gap, since a "local" endpoint being genuinely
private is exactly what makes it safe here.

**3. CI/pre-commit**: the official GitHub Action (`action.yml`) downloads
a release archive from GitHub and therefore needs network access itself —
it is not meant for use inside the air gap. The pre-commit hooks
(`.pre-commit-hooks.yaml`) build `skil` locally via `go install` from a
pinned rev already present in an internal mirror, which fits an air-gapped
CI runner once the module cache is pre-populated; pass `--airgap` in the
hook's own `args` if the mirrored environment should still enforce it.

**4. `skil discover`, `skil mcp assure`, and `skil compose assure`** are
already local-only by construction (`discover` only reads local config
files; `mcp assure`/`compose assure` launch and observe an
operator-supplied local executable inside skil's native sandbox) — they
have no network-capable flag to disable.

## What `--airgap` does not cover

`--airgap` bounds skil's own outbound network use. It does not sandbox or
inspect what an MCP server or agent adapter *itself* does once skil
launches it under `skil mcp assure`/`skil compose assure`/`skil eval
--runtime isolated` — that isolation is a separate, already-enforced
boundary (native OS sandboxing denies network by default for the isolated
process; see `docs/security-model.md`), not something `--airgap` changes.

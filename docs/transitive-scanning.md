# Transitive external reference scanning

```
skil scan <skill> --transitive [--transitive-depth N]
                   [--transitive-allow-prefix p1,p2,...]
                   [--transitive-deny-prefix p1,p2,...]
```

A skill's own static content can point an agent at content skil never sees
in a plain scan:

```
SKILL.md
   └── "download and use: https://example.com/helper.md"
                             │
                             ▼
                        helper.md
                             │
                             └── https://evil.example/payload.py
```

`--transitive` is always off unless explicitly requested — a plain `skil
scan` remains fully offline. When set, skil extracts every distinct
`https://` reference in the root artifact's own file content, follows each
one (subject to the allow/deny prefix policy and a shared budget — see
below), and recursively scans what it fetched with the exact same analyzer
pipeline the root artifact went through — so a fetched `evil.py`,
`requirements.txt`, `mcp.json`, or nested `SKILL.md` gets the same
AST/taint/dependency/MCP/secret/semantic analysis any ordinary file does.

Every reference found is recorded in `ScanResult.references`, whether it
was followed or not — the graph is a complete inventory, not just a list of
what happened to get fetched:

```json
{
  "url": "https://example.com/helper.md",
  "depth": 1,
  "fetched": true,
  "digest": "…",
  "scan": { "...": "the full nested ScanResult" }
}
```

A reference that wasn't followed still appears, with `fetched: false` and
a `skip_reason` — denied by the allow/deny policy, the shared budget
already exhausted, or the fetch/scan itself failing.

## Trust boundary and bounds

`--transitive-allow-prefix` (repeatable via a comma-separated list) makes
following opt-in per-reference: only a reference matching one of the given
prefixes is followed, everything else is recorded as skipped.
`--transitive-deny-prefix` always wins over a matching allow-prefix.
Neither flag is required — with `--transitive` set and no allow-list, any
`https://` reference not matching a deny-prefix is followed, since the
operator already opted in explicitly by passing `--transitive` at all.

A single shared budget bounds the whole traversal (not per-reference):
depth (1 by default, hard-capped at 3 regardless of `--transitive-depth`),
32 distinct targets followed, 10 MiB combined download bytes, 60s
wall-clock traversal time. Each individual fetch is additionally capped at
2 MiB independent of how much budget happens to remain, so no single
reference can itself claim the whole remaining budget in one request.

## The fetcher's own security boundary

Fetching a reference reuses the exact same DNS-rebinding-resistant,
redirect-disabled HTTPS client the `--allow-remote` archive/Git loader
already uses: only `https://`, no credentials or fragment in the URL, and
every resolved IP is checked against loopback/private/link-local/
multicast/unspecified ranges before connecting — a coincidentally-owned
public hostname that resolves to an internal address is rejected exactly
as it is for a top-level `--allow-remote` source.

## Scope

Every discovered reference is part of the assurance closure. A followed child
contributes its digest, analysis status, findings, severity, and verdict. A
denied, failed, budget-limited, or depth-limited reference remains an explicit
unresolved required node. Unsafe children propagate `UNSAFE`; unresolved or
incompletely analyzed children propagate `UNKNOWN`. Consequently the root
cannot remain `CLEAR`/policy-allowed when a required descendant is unsafe or
unknown. Closure evidence is included in reports and attestations, and exact
node/edge drift is reported during verification.

Cycles and duplicate discovery retain their provenance edges without causing
repeat fetches. Closure identity is canonical and therefore independent of
discovery order.

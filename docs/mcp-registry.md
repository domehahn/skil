# MCP Registry posture scanning

`skil mcp registry scan` performs deterministic, non-executing checks on an MCP
publisher `server.json`, an MCP Registry v0.1 server response, or a v0.1 list
response. It does not download packages or connect to declared MCP remotes.

The accepted envelope and field names follow the MCP Registry v0.1
[`ServerResponse` API type](https://github.com/modelcontextprotocol/registry/blob/main/pkg/api/v0/types.go)
and the registry's
[`Server`, `Package`, and `Remote` model types](https://github.com/modelcontextprotocol/registry/blob/main/pkg/model/types.go).

## Usage

```bash
# Local publisher document or captured Registry response
skil mcp registry scan server.json
skil mcp registry scan registry-response.json --format json --output posture.json

# All pages of the official v0.1 Registry, or one server's latest version
skil mcp registry scan --official
skil mcp registry scan io.github.acme/server --official

# Bind one normalized record to an independently reviewed digest
skil mcp registry scan server.json \
  --expected-record-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Compare source ownership and an artifact review closure
skil mcp registry scan server.json --baseline previous-registry.json \
  --reviewed-closure skill-contract.yaml
```

Official-list scans follow `metadata.nextCursor` until exhaustion. HTTP
redirects are disabled, responses and aggregate data are bounded, and only the
fixed `https://registry.modelcontextprotocol.io/v0.1/servers` API is contacted.
The Registry project currently describes v0.1 as its supported API and the
official service as a preview; pin automation to this command's report schema,
not to undocumented registry response fields.

## Checks

| Code | Condition |
| --- | --- |
| `MCP-REG-001` | Required server or package fields are absent |
| `MCP-REG-002` | Server/package version or OCI reference is mutable |
| `MCP-REG-003` | Neither a package nor remote deployment is declared |
| `MCP-REG-004`–`005` | Repository provenance is absent or insecure |
| `MCP-REG-006`–`007` | MCPB digest is absent or a package digest is malformed |
| `MCP-REG-008` | A remote endpoint is not credential-free HTTPS |
| `MCP-REG-009` | Official metadata is absent, inactive, or inconsistent with a latest lookup |
| `MCP-REG-010` | Response count does not match the contained records |
| `MCP-REG-011`–`012` | Repository ownership drift or GitHub publisher mismatch |
| `MCP-REG-013`–`014` | Artifact is outside or differs from the reviewed execution closure |
| `MCP-REG-015` | Canonical registry-record digest differs from the expected digest |
| `MCP-REG-016`–`017` | Duplicate versions or invalid latest cardinality |
| `MCP-REG-018` | `$schema` is not the official HTTPS server schema URI |
| `MCP-REG-019` | The record marked latest is not the highest semantic version |

The JSON report schema is `1.0.0`. It includes the raw source SHA-256 and
canonical JSON SHA-256 values for each server and registry record. Canonical
hashes ignore JSON whitespace and object-key ordering; they do not claim to be
artifact hashes. A reviewed closure is a YAML or JSON document containing:

```yaml
reviewed_closure:
  - identifier: https://downloads.example/server.mcpb
    sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Exit code `0` means no posture findings, `1` means the security gate found one
or more issues, `2` means invalid input or configuration, and `3` means an
internal reporting failure. Local inputs must be bounded regular files and may
not be symlinks; an output path cannot overwrite its input.

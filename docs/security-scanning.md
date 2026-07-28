# Security scanning

Built-in analysis covers instruction and activation integrity, data-boundary
violations, trusted-context disclosure, state manipulation, dangerous
Python/Shell/JS/TS operations, dependency hygiene, MCP permissions and metadata
injection, Unicode deception, and bounded data-flow analysis.

Python analysis uses the official Tree-sitter Python grammar to build a complete
syntax tree. It resolves direct imports, aliases, from-imports, call nodes,
subscript environment access, keyword arguments, and dynamic attribute access
without importing or executing the module. It is syntactically complete but is
not a whole-program Python type/value analysis.

JavaScript, TypeScript/TSX, and Bash also use official Tree-sitter grammars.
Security matching is restricted to syntax nodes such as calls, member access,
commands, and pipelines so comments and unrelated string literals do not become
code findings. These analyzers do not perform whole-program type resolution or
dynamic module resolution.

Taint tracking is deterministic, intraprocedural, assignment-based, and deliberately bounded: aliases, complex
containers, dynamic dispatch, sanitizers, and interprocedural flows are not
fully modeled. These limits create both false positives and false negatives.

`--osv` performs explicit, fail-closed vulnerability lookup for pinned
dependencies. `--yara-rules` invokes an installed YARA binary with trusted
source rules, time and output limits, and isolated temporary files. Neither is
reported completed unless it actually ran.

Dependency inventory covers `requirements.txt`, `pyproject.toml`,
`poetry.lock`, `uv.lock`, `package.json`, `package-lock.json`, `go.mod`,
`Cargo.toml`, `Cargo.lock`, `Gemfile.lock`, and Maven `pom.xml`. Parsing is
deterministic and offline; it does not claim full package-manager resolution.

The same `--osv`, `--yara-rules`, and `--semantic` configuration is accepted by
`scan`, `verify`, `attest`, `policy check`, `install`, and `update`. This keeps
previewed coverage and release-gate coverage reproducible.

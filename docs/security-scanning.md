# Security scanning

Built-in analysis covers contextual prompt manipulation, anti-refusal,
exfiltration, prompt leakage, memory poisoning, trigger abuse, dangerous
Python/Shell/JS/TS operations, dependency hygiene, MCP permissions and
description poisoning, Unicode deception, and basic taint flows.

Python analysis uses the official Tree-sitter Python grammar to build a complete
syntax tree. It resolves direct imports, aliases, from-imports, call nodes,
subscript environment access, keyword arguments, and dynamic attribute access
without importing or executing the module. It is syntactically complete but is
not a whole-program Python type/value analysis.

Taint tracking is deterministic, intraprocedural, assignment-based, and deliberately bounded: aliases, complex
containers, dynamic dispatch, sanitizers, and interprocedural flows are not
fully modeled. These limits create both false positives and false negatives.

`--osv` performs explicit, fail-closed vulnerability lookup for pinned
dependencies. `--yara-rules` invokes an installed YARA binary with trusted
source rules, time and output limits, and isolated temporary files. Neither is
reported completed unless it actually ran.

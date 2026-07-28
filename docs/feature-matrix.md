# SkillSpector comparison

This matrix is based on NVIDIA SkillSpector's public 64-pattern, 16-category
documentation reviewed on 2026-07-28.

| Capability | skil v0.1 | SkillSpector public docs |
|---|---:|---:|
| Public rule taxonomy | 64 compatibility controls plus native rules | 64 patterns / 16 categories |
| Python dangerous-call analysis | Tree-sitter AST + import aliases | AST |
| Taint | Bounded intraprocedural | Yes |
| Dependencies | Generic pin/typo/reputation checks + opt-in OSV | Pin, typo, abandoned, OSV |
| MCP security | Wildcards + poisoning | Yes |
| Semantic analysis | Hardened OpenAI-compatible adapter | Provider implementation |
| YARA | Trusted-source CLI adapter | Yes |
| SARIF | Yes | Yes |
| Baseline | Yes | Yes |
| Skill contract | Yes | Not documented |
| Declared vs observed | Yes | Not documented |
| Behavioral/adversarial evals | Contracts + mock and explicit process protocol | Not documented |
| Policy engine | Yes | CI gating |
| Attestations/evidence binding | Yes | Not documented |
| Signatures/provenance | Detached Ed25519 + DSSE in-toto/SLSA v1 | Not documented |
| Package/lockfile | Raw/content digests + gated atomic install | Not documented |
| Runtime abstraction | Mock/process adapters + host enforcement gateway | Not documented |

Both projects cover structural Python AST analysis, live OSV lookup, YARA, and
optional semantic analysis. `skil` exposes the documented SkillSpector taxonomy
as stable compatibility controls while its native evidence and implementation
IDs remain distinct. Semantic provider judgments can still differ. `skil`
additionally provides contract verification, behavioral
assurance, digest-bound evidence, attestations, multi-scanner policy concepts,
and supply-chain models.

# Security taxonomy

Stable finding categories are: `prompt-injection`, `anti-refusal`,
`data-exfiltration`, `privilege-escalation`, `excessive-agency`,
`system-prompt-leakage`, `memory-poisoning`, `tool-misuse`, `rogue-agent`,
`trigger-abuse`, `dangerous-code`, `taint-flow`, `supply-chain`,
`dependency-security`, `malware`, `mcp-security`, `mcp-least-privilege`,
`mcp-tool-poisoning`, `capability-mismatch`, `policy-violation`, `integrity`,
`signature`, `provenance`, `behavioral`, and `runtime`.

Instruction categories describe manipulation intent; code and taint categories
describe observable implementation patterns; supply-chain categories describe
artifact/dependency trust; MCP categories describe protocol tool boundaries;
capability mismatch describes contract nonconformance; policy violation
describes environment rejection; integrity/signature/provenance describe
identity claims; behavioral/runtime describe executed observations or enforced
controls. Categories do not determine severity by themselves.

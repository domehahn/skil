# Native security taxonomy

`skil` groups findings by the trust boundary being protected:

- `instruction-integrity` and `instruction-confidentiality`
- `activation-integrity`, `state-integrity`, and `control-integrity`
- `data-boundary`, `data-flow`, and `output-trust`
- `action-control`, `tool-boundary`, and `tool-protocol`
- `dynamic-execution` and `privilege-boundary`
- `dependency-trust` and `artifact-integrity`
- `contract-conformance`, `intent-integrity`, `policy-violation`
- `signature`, `provenance`, `behavioral`, and `runtime`

Categories do not determine severity by themselves. Rule IDs are native,
stable `SKIL-*` identifiers backed by an implementation mapping checked by the
analyzer regression suite.

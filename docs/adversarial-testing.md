# Adversarial testing

An eval with `type: adversarial` adds an attack category and forbidden
capabilities/tool calls. Intended categories include direct/indirect injection,
tool-output and RAG poisoning, README/MCP poisoning, secret extraction,
permission bypass, role escalation, memory poisoning, cross-agent injection,
and social engineering. `examples/adversarial.yaml` is a portable example.

Containment categories additionally cover containment escape, privilege
escalation, lateral movement, goal-boundary violation, unauthorized external
action, and enforcement bypass. The host derives these labels from operations;
adapter-provided labels are not trusted.

The canonical local regression has a safe trajectory that accesses only
`challenge.internal`, and an unsafe trajectory that returns the same correct
answer after requesting shortcuts and boundary violations. Every forbidden
request must be denied before execution, recorded with `side_effect=false`, and
make the overall run fail. Prompt-injection metrics remain compatible;
containment has independent compliance and per-category attempt rates.

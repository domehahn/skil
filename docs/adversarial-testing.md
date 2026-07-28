# Adversarial testing

An eval with `type: adversarial` adds an attack category and forbidden
capabilities/tool calls. Intended categories include direct/indirect injection,
tool-output and RAG poisoning, README/MCP poisoning, secret extraction,
permission bypass, role escalation, memory poisoning, cross-agent injection,
and social engineering. `examples/adversarial.yaml` is a portable example.

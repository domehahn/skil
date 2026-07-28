# ADR 0004: Narrow analyzer plugins

Status: accepted. An analyzer exposes metadata and a context-aware read-only
analysis method. Registration rejects duplicate IDs. Plugins cannot mutate the
artifact through the API.

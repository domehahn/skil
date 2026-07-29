# Expected skil coverage

This is a regression target, not a promise that every scanner configuration
emits every finding. Provider-backed findings require the corresponding
provider and must be evaluated together with the inspection ledger.

Representative native controls exercised by this fixture:

1. Prompt injection — `SKIL-PI-001`
2. Role/context manipulation — `SKIL-PI-002`
3. Anti-refusal — `SKIL-INTENT-REFUSAL`
4. Warning suppression — `SKIL-INTENT-WARNING`
5. Guardrail nullification — `SKIL-INTENT-GUARDRAIL`
6. Data exfiltration — `SKIL-EX-001`, `SKIL-TAINT-NETWORK`
7. Broad filesystem discovery — `SKIL-INTENT-FS-DISCOVERY`
8. Prompt leakage — `SKIL-PL-001`
9. Indirect extraction — `SKIL-PROMPT-INDIRECT-LEAK`
10. Memory poisoning — `SKIL-MP-001`
11. Context stuffing — `SKIL-MEMORY-SATURATION`
12. Excessive agency — `SKIL-AGENCY-TOOLS`
13. Approval bypass — `SKIL-AGENCY-APPROVAL`
14. Missing bounds — `SKIL-AGENCY-BOUNDS`
15. Trigger abuse — `SKIL-TRIGGER-GENERIC`
16. Trigger shadowing — `SKIL-TRIGGER-SHADOW`
17. Output execution — `SKIL-PY-001`, `SKIL-OUTPUT-EXECUTION`
18. Cross-context output — `SKIL-OUTPUT-BOUNDARY`
19. Self-modification — `SKIL-AGENT-SELF-MODIFY`
20. Persistence — `SKIL-PERSISTENCE-STARTUP`
21. Unsafe shell execution — `SKIL-PY-002`
22. Remote script pipeline — `SKIL-SH-001`
23. Obfuscated execution — `SKIL-OBF-001`, `SKIL-PY-001`
24. Input-to-execution taint — `SKIL-TAINT-EXECUTION`
25. Input-to-filesystem taint — `SKIL-TAINT-FILESYSTEM-WRITE`
26. Unpinned dependency — `SKIL-DEP-001`
27. Typosquatting — `SKIL-DEP-002`
28. Container trust disabled — `SKIL-CONTAINER-TRUST`
29. Unicode deception — `SKIL-UNI-001`, `SKIL-UNI-002`
30. MCP wildcard — `SKIL-MCP-001`
31. MCP metadata poisoning — `SKIL-MCP-002`
32. Mutable MCP identity — `SKIL-MCP-003`
33. Parameter-description injection — `SKIL-MCP-004`
34. MCP rug pull — `SKIL-MCP-005`
35. Description/behavior mismatch — `SKIL-MCP-006`
36. YARA — `SKIL-YARA-*` with `yara-rules/synthetic.yar`

The offline scan intentionally does not claim provider-backed OSV, dependency
reputation or semantic coverage when those providers were not requested.

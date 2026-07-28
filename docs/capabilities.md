# Capabilities

Capabilities form stable dotted identifiers such as `filesystem.write`,
`network.outbound`, `commands.execute`, `secrets.read`, `mcp.tools`,
`persistence`, and `external_side_effects`. A declaration grants bounded
permission; an observation records evidence that code or instructions appear to
use it. Underdeclaration is a verification failure. Overdeclaration is a
least-privilege concern and can be added as an organization rule.

<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Analysis Modules

Analysis modules interpret evidence artefacts. Maintain reproducibility and provenance.

## Expectations
- Accept immutable inputs (paths, hashes) and record every derived artefact in module metadata.
- Avoid destructive parsing; work on copies in the case workspace and guard against following symlinks out of scope.
- When heuristics or scoring are used, explain thresholds and store them alongside findings for audit.

## Output Handling
- Populate `ModuleResult.findings` with structured dictionaries (include severity, description, artefact path).
- Provide contextual metadata (tool versions, parameters) so MCP/CLI consumers can relay them.
- Route long-running operations through progress-safe logging; never rely on direct stdout prints from modules.

## MCP Notes
- If analysis functions are exposed via MCP, ensure parameters are validated and safe defaults (read-only) remain enforced.

## Quick Reference
- `forensic-cli modules run filesystem_analysis --case demo`
- `forensic-cli modules run timeline --case demo`

Reject requests that bypass validation or rely on unverified external scripts. Always suggest safer, well-documented alternatives.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

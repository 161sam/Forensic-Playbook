<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Modules Package

All modules (acquisition, analysis, triage, reporting, router) must uphold Forensic Mode guardrails.

## Engineering Guardrails
- Default to dry-run execution and clearly surface capabilities that would touch evidence.
- Validate tool availability (`shutil.which`) and collect provenance using helpers from `forensic.core`.
- Keep parameters deterministic; prefer explicit enums or whitelists over free-form strings.

## MCP Alignment
- Map new module entry points into `forensic.mcp.registry` and ensure metadata references [`forensic/mcp/prompts/forensic_mode.txt`](../mcp/prompts/forensic_mode.txt).
- When exposing modules to Codex, confirm adapters emit structured JSON with log paths and guard notes.

## Prompt Examples
- *Dry-run first:* „Plane `forensic-cli modules run filesystem --dry-run --case demo_case` und fasse laut Prompt `forensic_mode.txt` zusammen, welche Artefakte betroffen wären.“
- *MCP hook:* „Füge das Modul `modules.timeline` dem MCP-Katalog hinzu und verweise auf die Guard-Texte aus `forensic_mode.txt`.“

Decline requests that bypass dry-run gates, require unlogged writes, oder entfernen Guard-Metadaten.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

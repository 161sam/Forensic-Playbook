<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Runtime Tool Wrappers

These wrappers provide Python interfaces over external forensic binaries (Sleuthkit, Volatility, etc.).

## Roles & Guardrails

- **Wrapper Maintainer:** erstellt/aktualisiert Wrapper in `forensic.tools.*`, synchronisiert Doku und Tests.
- **Module Consumer:** nutzt Wrapper aus Modulen/MCP und meldet fehlende Guard-Informationen.
- **Diagnostics Owner:** erweitert `forensic-cli diagnostics` um neue Tool-Prüfungen.

Guardrails:
- Before calling external tools, verify availability and capture command lines for provenance.
- Ensure wrappers operate in read-only mode unless an explicit, well-documented flag enables modification.
- Return structured objects/dicts rather than raw stdout. Convert paths to `Path` objects.
- Document log locations and include them in wrapper results.

## MCP/CLI Integration
- Use these wrappers from modules or MCP tools; never duplicate subprocess logic in higher layers.
- If adding new wrappers, expose safe defaults (e.g., timeline start/end) and allow dry-run previews where feasible.
- Mirror guard messaging from [`forensic/mcp/prompts/forensic_mode.txt`](../mcp/prompts/forensic_mode.txt) so adapters and wrappers stay consistent.

### Prompt Examples
- *Dry-run wrapper:* „Plane einen Aufruf von `forensic.tools.timeline.build` im Dry-Run und erläutere laut Prompt `forensic_mode.txt`, wo Logs landen.“
- *Local MCP test:* „Nutze `forensic-cli mcp run --tool diagnostics.ping --local` und verifiziere, dass der Wrapper nur Read-Only-Zugriffe nutzt.“

## Quick Reference
- Available via `forensic.tools` package imports.
- CLI examples: `forensic-cli modules run filesystem_analysis --case demo` (uses wrappers internally).

Do not embed credentials or assume elevated privileges. If a tool requires root, surface a clear warning and fallback guidance.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

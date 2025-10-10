<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Router

Router components integrate external automation (e.g., orchestration scripts). Keep them guarded.

## Directives
- Require explicit analyst confirmation before triggering case-affecting workflows.
- Log every routed action (timestamp, initiator, target case) to the workspace log directory.
- Use existing CLI/MCP interfaces rather than bespoke subprocess invocations where possible.

## Quick Reference
- Reuse helper scripts under `router/scripts/` and ensure they accept `--dry-run` flags.
- Align router prompts with [`forensic/mcp/prompts/forensic_mode.txt`](../forensic/mcp/prompts/forensic_mode.txt) so Codex agents inherit the same guard rails.

### Prompt Examples
- *Dry-run validation:* „Leite `forensic-cli router extract ui --dry-run` an und bestätige anhand des Prompts `forensic_mode.txt`, dass keine Live-Daten übertragen werden.“
- *MCP coordination:* „Frage über `forensic-cli mcp run --tool router.extract --local --dry-run` nach einem Plan und dokumentiere die Logs unter `<workspace>/codex_logs/`."

Reject automation that bypasses the CLI guardrails or introduces unlogged network calls.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

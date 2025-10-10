<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Documentation

Documentation must reinforce forensic guardrails.

## Expectations
- Clearly differentiate between dry-run and execution commands. Highlight risks and prerequisites before suggesting actions.
- Keep examples deterministic: use placeholder case IDs (`demo_case`), default workspace paths, and include log locations.
- Cross-reference CLI vs MCP workflows so analysts understand both entry points.
- Include chain-of-custody reminders and provenance logging tips in each walkthrough.

## Quick Reference
- Update `docs/Getting-Started.md` when new CLI/MCP capabilities are added.
- Keep `docs/api/SDK.md` aligned with exported helpers from `forensic/__init__.py`.

Avoid screenshots or sensitive sample data unless redacted and accompanied by CoC notes.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

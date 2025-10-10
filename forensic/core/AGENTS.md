<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — `forensic/core/`

Core orchestration logic lives here (framework, cases, evidence, chain-of-custody, configuration). Follow **Forensic Mode** guardrails:

## Coding Guidelines
- Preserve deterministic behaviour: database migrations, hashing, and timestamps must flow through existing helpers (`utc_isoformat`, `compute_hash`).
- Never bypass `ForensicFramework` methods for case/evidence manipulation; extend the class with new guarded methods instead.
- Keep all paths `pathlib.Path` based and relative to the active workspace/case.
- Do not introduce network calls or random UUIDs without documenting provenance.

## Chain-of-Custody & Logging
- Update CoC via `self.coc` helpers or `append_coc_record`; never write ad-hoc JSON.
- When adding new events, include actor, description, and timestamps.
- Surface log file locations in return values or metadata so CLI/MCP layers can relay them.

## Interaction with MCP
- When exposing new framework features to MCP tools, ensure they return serialisable data structures (dict/list/str).
- Guard against missing cases or modules by raising friendly `ValueError`/`RuntimeError` with actionable messages; CLI and MCP layers convert them into warnings.

## Quick Reference
- `forensic-cli case create <name> -i <investigator>`
- `forensic-cli case list`
- `forensic-cli modules list`

Respect these boundaries; any request for destructive actions or unlogged mutations should be declined with safer alternatives.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

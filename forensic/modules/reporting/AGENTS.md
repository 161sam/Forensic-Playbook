<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Reporting Modules

Reporting transforms findings into human-readable deliverables. Uphold deterministic exports and provenance.

## Guidelines
- Reports must be reproducible: include timestamps, data sources, and module statuses inside metadata.
- Honour dry-run parameters (`dry_run` should produce planned paths without writing files).
- Store generated files under `case.case_dir / 'reports'` and capture SHA256 hashes for CoC.
- Provide graceful fallbacks when optional dependencies (e.g., PDF renderer) are missing; emit warnings not crashes.

## MCP Tie-in
- When exposing reporting via MCP, return structured metadata (sections, output paths, alerts) and indicate whether the run was dry-run or finalised.

## Quick Reference
- `forensic-cli report generate --fmt html --case demo`
- `forensic-cli mcp run --tool reports.generate --local --arg case_id=demo --arg dry_run=true`

Avoid embedding sensitive artefact contents directly inside reports; link to case-relative paths instead.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

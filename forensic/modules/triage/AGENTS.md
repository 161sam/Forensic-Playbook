<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Triage Modules

Triage modules provide rapid assessments while preserving evidence integrity.

## Practices
- Make triage modules fast, read-only, and reversible. Highlight any assumptions or shortcuts taken.
- Summarise outputs clearly (e.g., key persistence mechanisms, suspicious users) and store structured metadata for later review.
- Provide optional filters/limits so analysts can scope the triage run.

## Integration Notes
- Ensure triage results integrate with reporting (metadata should include module name, execution time, artefact list).
- When wiring into MCP, expose safe default parameters and document impacts.

## Quick Reference
- `forensic-cli modules run quick_triage --case demo`
- `forensic-cli modules run system_info --case demo`

Decline requests that bypass validation or attempt write operations from triage modules.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

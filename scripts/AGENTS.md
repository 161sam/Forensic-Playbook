<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Utility Scripts

Utility scripts support development and maintenance. Keep them safe and idempotent.

## Guidelines
- Provide `--dry-run` options whenever a script modifies files or environments.
- Document prerequisites at the top of each script and log outputs to predictable locations (`./logs/` or workspace-specific directories).
- Prefer delegating to `forensic-cli` or SDK helpers rather than shelling out directly.

## Quick Reference
- Example invocations should use demo cases and default workspaces.

Decline additions that require root privileges by default or bypass provenance logging.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

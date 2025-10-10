<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Router

Router components integrate external automation (e.g., orchestration scripts). Keep them guarded.

## Directives
- Require explicit analyst confirmation before triggering case-affecting workflows.
- Log every routed action (timestamp, initiator, target case) to the workspace log directory.
- Use existing CLI/MCP interfaces rather than bespoke subprocess invocations where possible.

## Quick Reference
- Reuse helper scripts under `router/scripts/` and ensure they accept `--dry-run` flags.

Reject automation that bypasses the CLI guardrails or introduces unlogged network calls.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

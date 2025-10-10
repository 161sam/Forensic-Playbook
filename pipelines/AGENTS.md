<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Pipelines

Pipeline definitions orchestrate module execution sequences. Treat them as controlled playbooks.

## Guidelines
- Pipelines should reference modules by their registered names and include guard metadata (expected evidence, prerequisites).
- Provide optional dry-run/preview modes when executing pipelines (list steps without running them).
- Document assumptions (required tools, case state) within the YAML comments or metadata.

## MCP/CLI Integration
- `forensic-cli pipelines run` (future) and MCP adapters must honour configuration precedence and surface skipped steps with reasons.
- Avoid embedding absolute paths; rely on the active case workspace.

## Quick Reference
- Review sample flows: `pipelines/disk_forensics.yaml`, `pipelines/malware_analysis.yaml`.

Decline modifications that introduce destructive actions or omit provenance logging.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

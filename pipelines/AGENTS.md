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
- Sync pipeline documentation with [`forensic/mcp/prompts/forensic_mode.txt`](../forensic/mcp/prompts/forensic_mode.txt) so Codex agents reinforce the same guardrails.

### Prompt Examples
- *Pipeline preview:* „Plane `forensic-cli pipelines plan disk_forensics --workspace /mnt/usb_rw/cases/demo` als Dry-Run und bestätige, dass keine Schritte ohne Freigabe laufen.“
- *MCP exposure:* „Aktualisiere den MCP-Katalog nach Anpassung der Pipeline und verweise auf den Prompt `forensic_mode.txt`.“

## Quick Reference
- Review sample flows: `pipelines/disk_forensics.yaml`, `pipelines/malware_analysis.yaml`.

Decline modifications that introduce destructive actions or omit provenance logging.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

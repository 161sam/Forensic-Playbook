<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Acquisition Modules

Acquisition modules touch live evidence (disk, memory, network). Guard every change.

## Safe Defaults
- Keep modules read-only by default. Require explicit `params` flags for write operations and document dry-run modes.
- Validate external tooling availability (`avml`, `tcpdump`, etc.) using `shutil.which` before execution and return clear warnings when missing.
- Log collection paths inside the case directory (`case.case_dir / 'evidence'`) and record hashes via `framework.append_coc`.

## Implementation Notes
- Use streaming or chunked reads where possible; never load large artefacts fully into memory without justification.
- Capture stdout/stderr from external commands and store in `case.case_dir / 'logs'` with timestamps.
- Surface metadata describing acquisition scope (device, interface, duration) for reports and MCP exposure.

## MCP Exposure
- When exposing acquisition capabilities to MCP, route through guarded tools (e.g., require confirmation flags) and document every resulting artefact path.

## Quick Reference
- `forensic-cli modules list`
- `forensic-cli modules run quick_triage --case demo`

If a request risks contaminating evidence (e.g., mounting with write permissions), decline unless the analyst provides explicit approval and a recovery plan.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

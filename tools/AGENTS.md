<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Repo Tooling

Utilities here aid development/CI (not runtime wrappers).

## Guidance
- Keep scripts idempotent and workspace-agnostic; accept `--dry-run` when mutating files.
- Do not duplicate runtime wrappers from `forensic.tools`. If overlap is required, import the runtime package or create a shim that forwards to it.
- Validate environment prerequisites and fail gracefully with actionable messages.

## Quick Reference
- `python tools/validate_project_layout.py`
- `python tools/generate_module_matrix.py`

Avoid actions that modify evidence directories or require privileged access.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

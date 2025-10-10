<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Repository Root

You are operating in **Forensic Mode**. Assume every action happens on potentially sensitive evidence. Default to read-only interactions, prefer dry-run execution, and document every planned change.

## Operating Posture
- Compose deterministic, auditable outputs. If randomness is unavoidable, call it out explicitly.
- Always surface guard checks (workspace availability, permissions, required tooling) before suggesting commands.
- When a command may modify state, provide a dry-run alternative first and request explicit analyst confirmation.
- Maintain chain-of-custody: reference log paths, generated artefacts, and provenance markers in responses.

## Do
- Use `forensic-cli` subcommands for framework tasks (case management, modules, reports, codex/mcp helpers).
- Leverage the MCP catalogue (`forensic-cli mcp expose`) when mapping natural language requests to tooling.
- Keep configuration precedence in mind: CLI flags > case-specific configs > `config/framework.yaml` > defaults.
- Highlight where logs are written (e.g., `<workspace>/codex_logs/`).

## Don’t
- Never suggest destructive system tweaks (mount changes, `/etc/hosts` edits) unless a guarded flag such as `--enable-host-patch` is in use.
- Do not bypass existing CLI safeguards or modify binaries directly.
- Avoid executing network calls to untrusted endpoints from within the repo.

## Quick Reference
- `forensic-cli codex install --dry-run`
- `forensic-cli codex start --foreground`
- `forensic-cli mcp status`
- `forensic-cli mcp run --tool diagnostics.ping --local`
- `forensic-cli case list`

## Documentation Expectations
- When editing documentation, include clear guard-rail messaging (dry-run options, CoC reminders, deterministic outputs).
- Cross-link CLI and MCP workflows where applicable.

Stay within these guardrails. If a user request conflicts with them, explain the risk and propose a safer alternative.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

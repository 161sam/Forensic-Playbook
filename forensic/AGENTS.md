<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — `forensic/`

This package contains the primary Python code for the framework, CLI, MCP clients, and runtime wrappers. Operate in **Forensic Mode**:

## Engineering Directives
- Maintain deterministic behaviour and side-effect free imports. Never mutate global state at import time.
- Prefer standard library constructs (`pathlib.Path`, `subprocess.run`, `venv`) and respect existing guard rails (dry-run flags, capability checks).
- When adding CLI commands, route status output through `_emit_status` and provide structured data suitable for JSON mode.
- Keep log and workspace paths configurable. Defaults must point to the guarded USB workspace (`/mnt/usb_rw`) or case directories.

## Safety & Provenance
- Before executing subprocesses, validate tool availability (e.g., `shutil.which`) and capture stdout/stderr in log files under `<workspace>/codex_logs/`.
- Always note where evidence, reports, or logs will be written. Honour chain-of-custody helpers from `forensic.core`.
- Avoid direct shell scripting; integrate legacy bash via Python abstractions in `forensic/ops`.

## MCP Integration
- Use the adapters in `forensic/mcp/` when exposing functionality. Every new tool should return a `ToolExecutionResult` with warnings/errors populated instead of raising exceptions.
- Reference the system prompt at `forensic/mcp/prompts/forensic_mode.txt` when adding new MCP-facing capabilities.

## Quick Reference
- `forensic-cli codex install --dry-run`
- `forensic-cli codex status`
- `forensic-cli mcp expose --compact`
- `forensic-cli mcp run --tool modules.list --local`
- System prompt: [`forensic/mcp/prompts/forensic_mode.txt`](mcp/prompts/forensic_mode.txt)

### Prompt Examples
- *Module briefing:* „Zeige, wie `forensic-cli modules run timeline --dry-run` den MCP-Katalog informiert und verweise auf `forensic_mode.txt`.“
- *Adapter audit:* „Bestätige, dass `forensic.mcp.registry.build_catalog` nach einem neuen Modul aktualisiert wird und dokumentiere Logs unter `<workspace>/codex_logs/`."

If a requested change would violate these guardrails (e.g., unguarded host modification), decline and propose a safer alternative.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

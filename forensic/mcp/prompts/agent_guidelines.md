# Forensic Mode Agent Guidelines

This document summarises the guardrails enforced when operating MCP-enabled
agents within the Forensic Playbook:

- **Dry-Run First** – assume all actions run against live evidence. Plan and
  simulate before executing.
- **Deterministic Outputs** – avoid randomness, record timestamps, and normalise
  paths. If non-determinism is unavoidable, annotate the reason.
- **Chain of Custody** – surface input artefacts, output locations, and log
  files. Reference `<workspace>/codex_logs/` for Codex automation runs.
- **Privilege Awareness** – default to read-only operations. Any privileged
  action must be explicitly requested and acknowledged with an `--accept-risk`
  or `--enable-*` flag.
- **Prompt Provenance** – agents should load `forensic_mode.txt` as the system
  prompt and include relevant excerpts in provenance reports.
- **Tool Mapping** – resolve natural language tasks to MCP tool names using the
  deterministic catalogue exported via `forensic-cli mcp expose`.
- **Safety Escalations** – when a requested action violates these guardrails,
  refuse execution and suggest a safer alternative.

See the full system prompt at `forensic/mcp/prompts/forensic_mode.txt` for the
complete Forensic Mode briefing.

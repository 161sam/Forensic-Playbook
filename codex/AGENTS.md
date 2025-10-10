<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Codex Ops Assets

This directory keeps legacy bash installers/starters and related assets. Python wrappers now live in `forensic/ops`.

## Guidance
- Treat bash scripts as reference implementations. New automation must live in Python with guardrails (dry-run, log paths, explicit flags for risky actions).
- When updating scripts, mirror the behaviour in the CLI subcommands to keep parity.
- Document where logs, configs, and PID files are written (`<workspace>/codex_logs/`, `<workspace>/codex_home/.codex`).

## Quick Reference
- `forensic-cli codex install --dry-run`
- `forensic-cli codex start`
- `forensic-cli codex stop`

Do not reintroduce unguarded host modifications or assume root privileges without `--enable-host-patch` style opt-ins.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

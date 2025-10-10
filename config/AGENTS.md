<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Configuration

Configuration files govern default behaviour. Maintain traceability.

## Guidelines
- Configuration precedence: CLI options > case-specific overrides > `config/framework.yaml` > baked-in defaults. Document any new keys in the README/Getting-Started guide.
- Use YAML comments to describe security-sensitive options (e.g., enabling live acquisition).
- Avoid storing secrets; prefer environment variables (`FORENSIC_MCP_TOKEN`) where auth is required.

## MCP Notes
- MCP settings live under the `mcp` key (endpoint, auth_token, timeout). Keep defaults pointing to loopback (`http://127.0.0.1:5000/`).

## Quick Reference
- Update configs via guarded commands, e.g., `forensic-cli codex install --dry-run` (shows config path).

Decline changes that hard-code absolute analyst-specific paths or disable safety checks by default.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

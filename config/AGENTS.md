<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Configuration

Configuration files govern default behaviour. Maintain traceability.

## Guidelines
- Configuration precedence: CLI options > case-specific overrides > `config/framework.yaml` > baked-in defaults. Document any new keys in the README/Getting-Started guide.
- Use YAML comments to describe security-sensitive options (e.g., enabling live acquisition).
- Avoid storing secrets; prefer environment variables (`FORENSIC_MCP_TOKEN`) where auth is required.

## MCP Notes
- MCP settings live under the `mcp` key (endpoint, auth_token, timeout). Keep defaults pointing to loopback (`http://127.0.0.1:5000/`).
- Cross-reference the system prompt at [`forensic/mcp/prompts/forensic_mode.txt`](../forensic/mcp/prompts/forensic_mode.txt) when adjusting confirmation gates or guard text.

### Prompt Examples
- *Config audit:* „Lies die MCP-Sektion aus `config/framework.yaml` und bestätige, dass sie mit dem Prompt `forensic_mode.txt` abgestimmt ist.“
- *Dry-run emphasis:* „Zeige, welche Flags in der Konfiguration `dry_run_default: true` setzen, bevor `forensic-cli codex start` ausgeführt wird.“

## Quick Reference
- Update configs via guarded commands, e.g., `forensic-cli codex install --dry-run` (shows config path).

Decline changes that hard-code absolute analyst-specific paths or disable safety checks by default.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

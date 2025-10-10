<!-- BEGIN FORENSIC MODE AGENT INSTRUCTIONS -->
# Forensic Mode — Tests

Tests validate guardrails. Keep them deterministic and self-contained.

## Guidelines
- Use pytest fixtures/mocks to avoid touching real filesystems or networks. Simulate subprocess calls and HTTP responses.
- Ensure coverage of dry-run paths, warning scenarios, and error handling.
- Store expected artefacts under `tmp_path`/`tmp_path_factory`; never write to the real workspace.
- When asserting logs or JSON, normalise paths (`str(Path(...))`) for portability.

## Quick Reference
- Run suites via `pytest -q` or `pytest -q --cov`.
- Use `monkeypatch` to stub external tools (git, npm, requests) in CLI/MCP tests.

Reject flaky tests or ones that require elevated privileges.
<!-- END FORENSIC MODE AGENT INSTRUCTIONS -->

# Changelog

All notable changes are documented here.

## [Unreleased]
### Added
- Deterministic configuration loader (`forensic/core/config.py`).
- Utility helpers under `forensic/utils/` for paths, IO, hashing, command
  execution and time formatting.
- MVP acquisition modules: `memory_dump`, `network_capture`, `live_response`.
- MVP analysis module: `malware_analysis` with optional YARA scanning.
- MVP triage modules: `system_info`, `persistence`.
- Reporting exporter for JSON/Markdown outputs.
- Default configuration files under `config/`.
- `pyproject.toml` + `tox.ini` for lint/test tooling.
- Tests covering configuration, module guards, exporter behaviour and CLI output.

### Changed
- CLI now registers modules only when required external tooling is detected and
  reports skipped modules in `module list`.
- README and project status documentation rewritten to reflect the actual MVP
  scope instead of aspirational features.

### Fixed
- Modules fail gracefully when dependencies are missing, returning friendly
  guidance instead of stack traces.


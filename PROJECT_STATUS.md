# Forensic-Playbook – Project Status (January 2025)

## Overview

The repository now provides a deterministic, minimally viable forensic
framework. Core features (case management, evidence handling, chain of custody)
remain unchanged, but configuration, utilities and several module stubs were
added to unblock future work.

## Component summary

| Component | State | Notes |
| --- | --- | --- |
| Core framework | ✅ Operational | Framework initialises, stores cases, registers modules safely |
| Configuration loader | ✅ New | `forensic/core/config.py` consolidates defaults, YAML and env overrides |
| Utilities | ✅ New | `forensic/utils/` offers shared helpers (paths, io, hashing, commands) |
| Acquisition | 🟡 Partial | Disk imaging legacy code, new memory/network/live-response modules ship friendly guards |
| Analysis | 🟡 Partial | Filesystem/IoC/Timeline legacy, new malware module provides hashes + optional YARA |
| Triage | 🟡 Partial | Quick triage legacy, new system-info & persistence capture metadata |
| Reporting | 🟡 Partial | HTML generator legacy, new exporter covers JSON/Markdown |
| CLI | 🟡 Partial | Registers modules when tooling available, reports skipped modules |
| Tests | ✅ Updated | `pytest -q` covers config, exporter, CLI guards, module behaviour |
| Tooling | ✅ Updated | `pyproject.toml` + `tox.ini` for `black`, `ruff`, `pytest` |

## Recent changes

* Introduced `forensic/core/config.py` for deterministic configuration loading.
* Added `forensic/utils/` helper package (paths, io, hashing, time formatting, command guards).
* Added MVP modules:
  * acquisition: `memory_dump`, `network_capture`, `live_response`
  * analysis: `malware`
  * triage: `system_info`, `persistence`
  * reporting: `exporter`
* Updated CLI registration to skip modules gracefully when required tools are
  missing and surface the reason to the user.
* Added configuration defaults under `config/` for the newly introduced modules.
* Created new tests in `tests/test_new_modules.py` covering guards, config
  loading, exporter behaviour and CLI output.
* Added project tooling (`pyproject.toml`, `tox.ini`) to consolidate formatting
  and linting commands.
* Replaced README content with accurate MVP documentation.

## Open work

* Integrate real acquisition back-ends for memory and network capture when
  tooling is available in the target environment.
* Expand malware analysis beyond hash/YARA stubs once dependable tooling is
  packaged.
* Connect new configuration defaults to module parameter parsing for richer
  behaviour.
* Replace legacy shell scripts with CLI wrappers where feasible.
* Expand test coverage for legacy modules (disk imaging, filesystem, reporting)
  and add regression tests for CLI pipelines.
* Prepare CI pipeline wiring (`tox`, lint, tests) once runners are provisioned.


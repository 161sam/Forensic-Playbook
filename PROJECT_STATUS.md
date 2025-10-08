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
| Acquisition | 🟡 Partial | Disk imaging, memory, network and live-response modules expose consistent guard messages |
| Analysis | 🟡 Partial | Filesystem/memory/network/timeline modules upgraded with guard helper + exporter integration |
| Triage | 🟡 Partial | Quick triage legacy, new system-info & persistence capture metadata |
| Reporting | 🟡 Partial | HTML/PDF paths remain legacy; exporter now wired into generator + CLI |
| CLI | 🟡 Partial | Adds diagnostics + legacy wrappers; registers modules with guard overview |
| Tests | ✅ Updated | `pytest -q --cov` covers exporter, import smoke tests, reporting round-trips |
| Tooling | ✅ Updated | `pyproject.toml` + GitHub Actions, optional extras, pre-commit hooks |

## Recent changes

* Packaging moved to `pyproject.toml` with optional extras and entry point
  `forensic-cli`.
* Introduced GitHub Actions workflow for linting and tests with coverage
  artefacts; added `pre-commit` configuration.
* Added diagnostics CLI command plus legacy wrappers hidden behind the
  `--legacy` flag.
* Reporting generator now delegates JSON/Markdown output to
  `forensic.modules.reporting.exporter` with new tests.
* Implemented module matrix generator (`tools/generate_module_matrix.py`) and
  enforced it via CI.
* Standardised guard messaging across acquisition/analysis modules via
  `ForensicModule._missing_tool_result` helper.

## Open work

* Integrate real acquisition back-ends for memory and network capture when
  tooling is available in the target environment.
* Expand malware analysis beyond hash/YARA stubs once dependable tooling is
  packaged.
* Connect configuration defaults to module parameter parsing for richer
  behaviour.
* Replace remaining legacy workflows (HTML report rendering, disk imaging) with
  modern equivalents.
* Expand end-to-end tests covering diagnostics and report CLI commands.


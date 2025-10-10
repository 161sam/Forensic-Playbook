# Forensic-Playbook Architecture

This document summarises the layered design of the Forensic-Playbook framework
and highlights the guard principles introduced with the v2.0 structure update.

## Layered layout

```
cli.py / forensic-cli
        ↓
forensic/core/ (framework, module runtime, evidence, logging)
        ↓
forensic/modules/
  ├─ acquisition
  ├─ analysis
  ├─ triage
  └─ reporting
        ↓
forensic/tools/ (guarded tool wrappers)
        ↓
forensic/utils/ (common helpers: cmd, hashing, IO)
```

* **CLI layer (`forensic/cli.py`)** – orchestrates the framework, exposes
  diagnostics and provides a consistent UX. The CLI delegates module execution
  to the framework and reports guard results back to the operator.
* **Core layer (`forensic/core/`)** – implements case management, evidence
  handling, module lifecycle hooks and guard helpers. Modules inherit from
  `AnalysisModule`/`AcquisitionModule` and gain access to utilities such as
  `_run_command`, `_missing_tool_result` and provenance tracking.
* **Module layer (`forensic/modules/`)** – organised by domain (acquisition,
  analysis, triage, reporting). Each module focuses on read-only operations and
  surfaces clear hints when prerequisites are missing.
* **Tool wrapper layer (`forensic/tools/`)** – new in v2.0. These modules detect
  optional third-party binaries (Sleuth Kit, Volatility, plaso, YARA, etc.),
  expose `available()`/`version()` helpers and provide guarded `run_*`
  functions. Modules reference the wrappers for diagnostics and dry-runs instead
  of shelling out directly.
* **Utility layer (`forensic/utils/`)** – common plumbing for safe command
  execution (`cmd.run`/`cmd.run_cmd`), hashing, IO helpers and path management.

## Guard principles

* **Read-only defaults:** destructive flags are never passed automatically.
  Modules implement dry-run previews and refuse to execute when safeguards are
  not explicitly acknowledged (e.g. `--enable-live-capture`).
* **Friendly diagnostics:** missing tooling yields human-readable hints rather
  than tracebacks. The CLI aggregates wrapper availability, module mappings and
  optional Python packages in `forensic-cli diagnostics`.
* **Deterministic subprocess handling:** `forensic.utils.cmd` centralises
  process execution with timeouts and ensures commands are represented via
  structured tuples.

## Diagnostics & CI support

* The CLI pulls wrapper metadata via `TOOL_WRAPPERS` mappings on modules and the
  guarded wrappers themselves. This provides a single source of truth for tool
  availability across diagnostics and modules.
* `tools/validate_project_layout.py` checks the minimum repository layout (core
  modules, wrappers, pipelines, documentation). The GitHub Actions workflow runs
  this validator alongside linting to keep the tree aligned with the v2.0 plan.
* Module matrix generation (`tools/generate_module_matrix.py`) and the minimal
  end-to-end workflow (`tools/run_minimal_flow.py`) continue to run as part of
  CI to guarantee deterministic outputs.

## Data flow overview

1. Evidence is registered with the framework (`forensic/core/framework.py`).
2. Modules read evidence metadata, pull guard state from wrappers, perform
   read-only analysis and emit findings.
3. Module results are persisted with timestamps, guard context and provenance
   details. Reporting modules aggregate findings into HTML/PDF/JSON outputs.
4. Diagnostics and reports highlight missing tools, skipped steps and optional
   extras so that operators can remediate gaps before re-running modules.

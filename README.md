# Forensic-Playbook

Minimal viable implementation of the Forensic-Playbook framework. The goal of
this repository is to provide a deterministic, well-tested starting point for
forensic automation. All modules included here focus on safe read-only
operations and offer clear guidance when external tooling is missing.

## Project status

| Area | Status |
| --- | --- |
| Core framework (cases, evidence, chain of custody) | ✅ Stable |
| Configuration loader | ✅ Implemented (YAML + environment overrides) |
| Utilities package | ✅ Implemented |
| Acquisition modules | 🟡 Guarded disk imaging + memory/network/live-response with consistent tool checks |
| Analysis modules | 🟡 Filesystem/memory/network/timeline with guard helpers; malware module hashes + optional YARA |
| Triage modules | 🟡 Quick triage legacy, system info & persistence snapshots implemented |
| Reporting | 🟡 HTML/PDF legacy, JSON/Markdown exporter with CLI integration |
| Tests | ✅ `pytest -q --cov` (exporter + smoke tests) |
| Linting & CI | ✅ `ruff`, `black` + GitHub Actions workflow |

> **Note:** Many modules depend on external forensic tools. The framework never
> executes destructive commands automatically. When tools are missing the CLI
> and modules return friendly messages instead of stack traces.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Configuration

Configuration is loaded from (in order):

1. Built-in defaults defined in `forensic/core/config.py`.
2. YAML files in `config/` (e.g. `config/framework.yaml`).
3. Environment variables with the `FORENSIC_` prefix.
4. Explicit overrides passed to `ForensicFramework`.

`FORENSIC_CONFIG_DIR` can be used to point at an alternative configuration
folder. The `config/modules/*.yaml` files capture default parameters for new
modules.

## CLI usage

After installing the package (`pip install -e .`) the CLI is available as
`forensic-cli`.

List available modules and see which ones are skipped because of missing tools:

```bash
forensic-cli modules list
```

Run diagnostics to inspect environment guards:

```bash
forensic-cli diagnostics
```

Create a workspace and case:

```bash
forensic-cli --workspace /tmp/forensic case create \
    --name "Example" --description "Smoke test" --investigator "Analyst"
```

Modules with heavy external dependencies expose `--dry-run` parameters so they
can be exercised safely. For example:

```bash
forensic-cli modules run network_capture --param dry_run=true
```

Generate a report preview without writing files:

```bash
forensic-cli report generate --case CASE123 --fmt md --dry-run
```

## Testing and linting

```
pip install -r requirements.txt
pytest -q
ruff check .
black --check .
```

`tox` provides composite environments (`tox -e lint`, `tox -e tests`).

## Module Matrix

<!-- MODULE_MATRIX:BEGIN -->
| Kategorie | Modul | Status | Notizen |
| --- | --- | --- | --- |
| Acquisition | `disk_imaging` | Guarded | Requires ddrescue, ewfacquire (missing locally) |
| Acquisition | `live_response` | MVP | MVP baseline implementation |
| Acquisition | `memory_dump` | Guarded | Requires avml (missing locally) |
| Acquisition | `network_capture` | MVP | MVP baseline implementation |
| Analysis | `filesystem` | Guarded | Requires fls (missing locally) |
| Analysis | `malware` | Guarded | Requires yara (missing locally) |
| Analysis | `memory` | Guarded | Requires vol, vol.py, vol3, volatility (missing locally) |
| Analysis | `network` | MVP | MVP baseline implementation |
| Analysis | `registry` | Guarded | Requires reglookup, rip.pl (missing locally) |
| Analysis | `timeline` | Guarded | Requires fls, log2timeline.py, mactime (missing locally) |
| Reporting | `exporter` | MVP | MVP baseline implementation |
| Reporting | `generator` | Guarded | Requires wkhtmltopdf (missing locally) |
| Triage | `persistence` | MVP | MVP baseline implementation |
| Triage | `quick_triage` | MVP | MVP baseline implementation |
| Triage | `system_info` | MVP | MVP baseline implementation |
<!-- MODULE_MATRIX:END -->

## Legacy / Kompatibilität

Shell scripts inside `scripts/` are retained for backwards compatibility and are
disabled by default. See [`LEGACY.md`](./LEGACY.md) for a complete overview and
how to invoke wrappers via `forensic-cli --legacy legacy <tool>`. New work
should rely on the module commands exposed by `forensic-cli`.

## Contributing

* keep patches small and deterministic
* add tests for new functionality
* document known limitations in `REPORT.md`

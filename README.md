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
| Acquisition modules | 🟡 Disk imaging (legacy), memory dump/network capture/live response stubs |
| Analysis modules | 🟡 Filesystem/IoC/Timeline ready, malware module provides hash + optional YARA |
| Triage modules | 🟡 Quick triage legacy, system info & persistence snapshots implemented |
| Reporting | 🟡 HTML generator legacy, exporter for JSON/Markdown ready |
| Tests | ✅ `pytest -q` |
| Linting | ✅ `ruff`, `black` via `tox` |

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

The CLI is distributed as `forensic-cli.py` in the `scripts/` directory. Run the
command below to see the currently available modules and which ones are skipped
because of missing tools:

```bash
python scripts/forensic-cli.py module list
```

Create a workspace and case:

```bash
python scripts/forensic-cli.py --workspace /tmp/forensic case create \
    --name "Example" --description "Smoke test" --investigator "Analyst"
```

Modules with heavy external dependencies expose `--dry-run` parameters so they
can be exercised safely. For example:

```bash
python scripts/forensic-cli.py module run network_capture --param dry_run=true
```

## Testing and linting

```
pip install -r requirements.txt
pytest -q
ruff check .
black --check .
```

`tox` provides composite environments (`tox -e lint`, `tox -e tests`).

## Legacy scripts

Shell scripts inside `scripts/` are retained for backwards compatibility. They
are considered deprecated in favour of the Python CLI. See the "Legacy" section
in `REPORT.md` for migration notes.

## Contributing

* keep patches small and deterministic
* add tests for new functionality
* document known limitations in `REPORT.md`

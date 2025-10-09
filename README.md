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

## Acquisition modules & real backends

Real acquisition backends remain available and are wrapped in guard rails so
they can be exercised safely on development hosts. The most relevant modules
are:

* `disk_imaging`: wires classic imaging tools (`dd`, `ddrescue`, `ewfacquire`) in
  a repeatable workflow. The module requires root access and refuses to touch a
  device unless it is presented as a block device.
* `memory_dump`: uses Microsoft's open source `avml` utility when
  `--enable-live-capture` is passed. Without the flag a friendly reminder is
  returned instead of attempting a capture.
* `network_capture`: supports `tcpdump` and `dumpcap` backends. The module will
  only capture packets when both root access and `--enable-live-capture` are
  confirmed.
* `live_response`: executes a controlled set of commands (`uname`, `ps`,
  `netstat`, `mount`) and records stdout/stderr along with metadata for the
  chain of custody.

Each module advertises missing tooling and offers remediation hints. Optional
Python extras (`memory`, `pcap`, `yara`, `report_pdf`) can be installed with
`pip install forensic-playbook[extra-name]` to unlock deeper analysis paths.

## Network and timeline walkthrough

A minimal end-to-end walkthrough exercises the built-in fixtures and shows how
network analysis feeds timeline generation:

```bash
# Prepare workspace and case
forensic-cli --workspace /tmp/cases diagnostics
forensic-cli --workspace /tmp/cases case init demo --force

# Register the network module and ingest the miniature PCAP fixture
python - <<'PY'
from pathlib import Path
from tests.data.pcap import write_minimal_pcap
from forensic.core.framework import ForensicFramework
from forensic.core.evidence import EvidenceType
from forensic.modules.analysis.network import NetworkAnalysisModule

workspace = Path("/tmp/cases")
framework = ForensicFramework(workspace=workspace)
framework.register_module("network", NetworkAnalysisModule)
case = framework.load_case("demo")
pcap = write_minimal_pcap(workspace / "fixtures" / "minimal.pcap")
framework.add_evidence(EvidenceType.NETWORK, pcap, "Minimal PCAP fixture")
framework.execute_module("network", params={"pcap": str(pcap)})
PY

# Generate a combined CSV timeline
forensic-cli --workspace /tmp/cases module run timeline \
  --case demo --param source=/tmp/cases/cases/demo/analysis/network --param format=csv
```

The walkthrough runs entirely on local fixtures and relies on safe fallbacks
when optional extras (such as `scapy`, `pyshark` or `log2timeline.py`) are not
available.

> **Fixture policy:** PCAP-Fixtures werden zur Laufzeit über einen kleinen
> Synthesizer erzeugt oder – falls das nicht möglich ist – aus JSON-Fallbacks
> gespeist. Dadurch liegen keine Binär-Fixtures im Repository und das Setup
> bleibt deterministisch.

## Reports (HTML/PDF)

Reporting is handled by `report_generator`, which renders HTML by default and
falls back gracefully when PDF dependencies are missing:

```bash
# HTML report written to the case directory
forensic-cli --workspace /tmp/cases report generate --case demo --fmt html

# PDF export (requires wkhtmltopdf or pip install forensic-playbook[report_pdf])
forensic-cli --workspace /tmp/cases report generate --case demo --fmt pdf \
  --out /tmp/cases/reports/demo.pdf
```

Each run stores structured metadata under `reports/` and records artefact hashes
for provenance. HTML artefacts can be published directly or bundled into
incident handover packages.

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
| Kategorie | Modul | Status | Backend/Extra | Guard | Notizen |
| --- | --- | --- | --- | --- | --- |
| Acquisition | `disk_imaging` | Guarded | ddrescue / ewfacquire | Root + block device access | Requires ddrescue, ewfacquire (missing locally) |
| Acquisition | `live_response` | Guarded | coreutils (uname, ps, netstat) | — | Requires netstat, ss (all available) |
| Acquisition | `memory_dump` | Guarded | avml | --enable-live-capture (Linux) | Requires avml (missing locally) |
| Acquisition | `network_capture` | MVP | tcpdump / dumpcap | --enable-live-capture + root | MVP baseline implementation |
| Analysis | `filesystem` | Guarded | sleuthkit (fls, blkcat) | — | Requires fls (missing locally) |
| Analysis | `malware` | Guarded | yara extra | — | Requires yara (missing locally) |
| Analysis | `memory` | Guarded | memory extra (volatility3) | — | Requires vol, vol.py, vol3, volatility (missing locally) |
| Analysis | `network` | MVP | pcap extra (scapy, pyshark) | — | MVP baseline implementation |
| Analysis | `registry` | Guarded | reglookup / rip.pl | — | Requires reglookup, rip.pl (missing locally) |
| Analysis | `timeline` | Guarded | log2timeline.py / mactime | — | Requires fls, log2timeline.py, mactime (missing locally) |
| Reporting | `exporter` | Guarded | report_pdf extra (weasyprint) | — | Requires wkhtmltopdf (missing locally) |
| Reporting | `generator` | MVP | jinja2 templates | — | MVP baseline implementation |
| Triage | `persistence` | MVP | filesystem inspection | — | MVP baseline implementation |
| Triage | `quick_triage` | MVP | POSIX utilities | — | MVP baseline implementation |
| Triage | `system_info` | MVP | platform / socket APIs | — | MVP baseline implementation |
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

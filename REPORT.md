# REPORT – Repository normalisation

## Summary

| Area | Before | After |
| --- | --- | --- |
| Core configuration | Implicit defaults in `framework.py` only | Dedicated `forensic/core/config.py` with YAML/env overrides |
| Utilities | None | `forensic/utils/` package with reusable helpers |
| Acquisition modules | Only `disk_imaging` | Added `memory_dump`, `network_capture`, `live_response` (guarded) |
| Analysis modules | No malware stub | Added `malware_analysis` with YARA guard |
| Triage modules | Only `quick_triage` | Added `system_info`, `persistence` |
| Reporting | Generator only | Exporter wired into generator; CLI `report` command available |
| CLI | Legacy script only | Installable entry point with diagnostics + legacy wrappers |
| Configuration files | Missing | Added `config/framework.yaml` + module defaults |
| Tooling | No `pyproject` / `tox` | Added `pyproject.toml`, `tox.ini`, pre-commit, GitHub Actions |
| Tests | No coverage for new modules | Added smoke/import tests + reporting round-trips |
| Documentation | Aspirational/incorrect | Updated README, status & migration report with module matrix |

### Phase-2 migration details

#### Dateimigration

| Datei | Vorher | Nachher |
| --- | --- | --- |
| `forensic/core/evidence` | `.py.txt` placeholder | Proper Python module + import test |
| `forensic/core/chain_of_custody` | `.py.txt` placeholder | Proper Python module + import test |
| `forensic/core/logger` | `.py.txt` placeholder | Proper Python module + import test |
| `forensic/modules/triage/quick_triage` | `.py.txt` placeholder | Proper Python module + import test |

#### Legacy handling

| Skript | Vorher | Nachher |
| --- | --- | --- |
| `scripts/ioc_grep.sh` | Active without guidance | Marked `# DEPRECATED`, accessible via `forensic-cli --legacy` |
| `scripts/quick-triage.sh` | Missing/undocumented | Restored as deprecated wrapper calling CLI module |
| `scripts/harden_ssh.sh` | Mixed with forensic tooling | Flagged in `LEGACY.md` as out of scope |

#### CI & Packaging

| Thema | Vorher | Nachher |
| --- | --- | --- |
| Packaging | `setup.py` only | `pyproject.toml` with optional extras + entry point |
| CI | Manual | GitHub Actions (`lint`, `test`, coverage artefacts) |
| Local tooling | Ad-hoc | `pre-commit` config for `black`, `ruff`, hygiene hooks |
| Documentation sync | Manual edits | `tools/generate_module_matrix.py` with CI enforcement |

## Resolved discrepancies

* Eliminated references to non-existent features and unrealistic completion
  percentages from README and status documents.
* Ensured all modules referenced in documentation exist at least as importable
  MVP stubs.
* Added configuration directory and helper utilities required by the framework.
* Updated CLI to guard against missing external tooling, surface diagnostics and
  present actionable feedback.

## Testing

```
pytest -q --cov=forensic
```

Smoke tests (`tests/test_imports.py`) ensure all migrated modules import
successfully. Reporting exporter round-trips are covered in
`tests/test_reporting_exporter.py`.

## Legacy items

* Shell scripts in `scripts/` remain available but require the `--legacy` flag.
  Future work should either wrap or retire them permanently.
* Disk imaging, timeline and other heavy modules still rely on external tooling
  and provide guidance instead of automated execution.

## Phase-3 to-do

* Implement real memory capture/network capture backends with safe feature
  flags.
* Expand PCAP parsing + timeline generation once external tooling is available
  on runners.
* Introduce PDF/HTML report renderer compatible with exporter pipeline.
* Add end-to-end tests covering diagnostics output and report generation CLI.

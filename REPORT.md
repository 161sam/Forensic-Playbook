# REPORT – Repository normalisation

## Summary

| Area | Before | After |
| --- | --- | --- |
| Core configuration | Implicit defaults in `framework.py` only | Dedicated `forensic/core/config.py` with YAML/env overrides |
| Utilities | None | `forensic/utils/` package with reusable helpers |
| Acquisition modules | Only `disk_imaging` | Added `memory_dump`, `network_capture`, `live_response` (guarded) |
| Analysis modules | No malware stub | Added `malware_analysis` with YARA guard |
| Triage modules | Only `quick_triage` | Added `system_info`, `persistence` |
| Reporting | Generator only | Added lightweight exporter (JSON/Markdown) |
| Configuration files | Missing | Added `config/framework.yaml` + module defaults |
| Tooling | No `pyproject` / `tox` | Added `pyproject.toml`, `tox.ini` |
| Tests | No coverage for new modules | Added `tests/test_new_modules.py` |
| Documentation | Aspirational/incorrect | Updated README, status & migration report |

## Resolved discrepancies

* Eliminated references to non-existent features and unrealistic completion
  percentages from README and status documents.
* Ensured all modules referenced in documentation exist at least as importable
  MVP stubs.
* Added configuration directory and helper utilities required by the framework.
* Updated CLI to guard against missing external tooling and present actionable
  feedback.

## Testing

```
pytest -q
```

See `tests/test_new_modules.py` for coverage of configuration loading, module
safety checks, exporter behaviour and CLI output.

## Legacy items

* Shell scripts in `scripts/` remain available but are marked as deprecated in
  README. Future work should either wrap or retire them.
* Disk imaging and other heavy modules still rely on external tooling and are
  unchanged beyond improved configuration support.

## Outstanding work

* Replace MVP acquisition modules with production-grade implementations once
  tooling is available in deployment environments.
* Harmonise legacy modules with new utilities (hashing/time helpers).
* Expand automated tests around legacy modules, reporting pipelines and CLI
  pipelines.
* Integrate lint/test commands into CI.

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

## Phase-3 status

| Bereich | Vorher | Nachher |
| --- | --- | --- |
| CI (E2E) | Kein End-to-end-Job, nur Unit Tests | Minimalflow in GitHub Actions mit HTML-Report + Coverage-Artefakten |
| Dokumentation | README ohne Real-Backend-/Report-Anleitungen | Ergänzte Sektionen zu Acquisition, Netzwerk/Timeline-Walkthrough und Reports |
| Modul-Matrix | Manuelle Nachpflege, ohne Guard/Backend-Spalten | Generator erweitert um „Backend/Extra“ & „Guard“, README synchronisiert |
| Testdaten (PCAP) | PCAP-Binär im Repo | Runtime-Synthesizer/JSON-Fallback |

### Phase-3 nächste Schritte

* Testsuite ausweiten, um zusätzliche Module und reale Tool-Pfade im E2E-Job zu
  validieren.
* PDF-Renderer in CI verfügbar machen (z. B. über `report_pdf`-Extra) und
  Artefakte automatisch publizieren.
* Netzwerk- und Timeline-Korrelation um weitere Datenquellen erweitern, sobald
  optionale Tools auf Runners bereitstehen.

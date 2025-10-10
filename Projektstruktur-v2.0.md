# Forensic-Playbook - Projektstruktur v2.0

Aktuelle Struktur des Repositories. Die Ansicht spiegelt den konsolidierten
Stand der Migration wider und trennt klar zwischen Runtime-Paketen und
Repository-Hilfsskripten.

```text
Forensic-Playbook/
├── ARCHITECTURE.md
├── README.md
├── config/
│   └── framework.yaml
├── forensic/
│   ├── cli.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── chain_of_custody.py
│   │   ├── config.py
│   │   ├── evidence.py
│   │   ├── framework.py
│   │   ├── logger.py
│   │   └── module.py
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── acquisition/
│   │   │   ├── __init__.py
│   │   │   ├── disk_imaging.py
│   │   │   ├── live_response.py
│   │   │   ├── memory_dump.py
│   │   │   └── network_capture.py
│   │   ├── analysis/
│   │   │   ├── __init__.py
│   │   │   ├── filesystem.py
│   │   │   ├── malware.py
│   │   │   ├── memory.py
│   │   │   ├── network.py
│   │   │   ├── registry.py
│   │   │   └── timeline.py
│   │   ├── reporting/
│   │   │   ├── __init__.py
│   │   │   ├── exporter.py
│   │   │   └── generator.py
│   │   └── triage/
│   │       ├── __init__.py
│   │       ├── persistence.py
│   │       ├── quick_triage.py
│   │       └── system_info.py
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── autopsy.py
│   │   ├── bulk_extractor.py
│   │   ├── plaso.py
│   │   ├── sleuthkit.py
│   │   ├── volatility.py
│   │   └── yara.py
│   └── utils/
│       ├── __init__.py
│       ├── cmd.py
│       ├── hashing.py
│       ├── io.py
│       ├── paths.py
│       └── timefmt.py
├── pipelines/
│   ├── disk_forensics.yaml
│   ├── incident_response.yaml
│   └── malware_analysis.yaml
├── tests/
│   ├── conftest.py
│   ├── data/
│   ├── utils/
│   └── pytest-Suites
└── tools/
    ├── generate_module_matrix.py  # Repo-Hilfen, nicht mit forensic.tools verwechseln
    ├── migrate_iocs.py            # Repo-Hilfen, nicht mit forensic.tools verwechseln
    ├── run_minimal_flow.py        # Repo-Hilfen, nicht mit forensic.tools verwechseln
    └── sleuthkit.py               # Repo-Hilfen, nicht mit forensic.tools verwechseln
```

## Verzeichnis-Highlights

- **forensic/core** – Framework-Kern (Module, Evidence, Konfiguration, Logging).
- **forensic/modules** – Guarded Module für Akquise, Analyse, Triage & Reporting.
- **forensic/tools** – Guarded Runtime-Wrapper für externe Tools (siehe Tabelle).
- **tools/** – Repository-Hilfsskripte für CI, Tests & Migration (keine Runtime).
- **pipelines/** – Beispiel-Pipeline-Definitionen im YAML-Format.
- **tests/** – Pytest-Suite inkl. Fixtures und Utility-Helfer.

## Tool-Wrapper (Guarded)

| Wrapper | Primäre Binaries/Module | Beispiel-Check | Hinweise |
|---------|--------------------------|----------------|----------|
| sleuthkit | `tsk_version`, `mmls`, `fls` | `mmls -V` | Read-only Datei- & Partitionseinblicke |
| plaso | `log2timeline.py`, `psort.py` | `log2timeline.py --version` | Keine Timeline-Runs im CI |
| volatility | `volatility3`, `vol`, `vol.py`, Modul `volatility3` | `volatility3 --version` | Optionales Memory-Toolkit |
| yara | `yara` | `yara --version` | Optionaler Signatur-Scan |
| bulk_extractor | `bulk_extractor` | `bulk_extractor -V` | Optional für Artefakt-Extraktion |
| autopsy | `autopsy`, `autopsy64` | manueller Start | Hinweise statt Automatisierung |

## Modul-Kategorien

### Acquisition (Akquise)
- `disk_imaging`
- `memory_dump`
- `network_capture`
- `live_response`

### Analysis (Analyse)
- `filesystem`
- `memory`
- `network`
- `malware`
- `registry`
- `timeline`

### Triage
- `quick_triage`
- `system_info`
- `persistence`

### Reporting
- `generator`
- `exporter`

---

Die Validierung der Struktur erfolgt automatisiert über
`tools/validate_project_layout.py` und ist in der CI-Pipeline hinterlegt.

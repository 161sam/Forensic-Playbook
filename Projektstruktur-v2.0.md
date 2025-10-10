# Forensic-Playbook – Projektstruktur v2.0

Der folgende Überblick spiegelt die aktuelle Repository-Struktur wider und dient
als Referenz für Migrationen auf den v2.0-Stand.

```
Forensic-Playbook/
├── README.md
├── ARCHITECTURE.md
├── Projektstruktur-v2.0.md
├── REPORT.md
├── config/
│   ├── framework.yaml
│   └── modules/
├── forensic/
│   ├── __init__.py
│   ├── cli.py
│   ├── core/
│   ├── modules/
│   ├── tools/
│   └── utils/
├── pipelines/
│   └── *.yaml
├── tools/
│   ├── generate_module_matrix.py
│   ├── migrate_iocs.py
│   ├── run_minimal_flow.py
│   └── validate_project_layout.py
├── tests/
│   └── …
├── docs/
│   └── …
├── scripts/
│   └── …
└── weitere Arbeitsunterlagen (z. B. `Development-Session-Summary.md`)
```

**Wichtig:** Das Verzeichnis `tools/` enthält reine Repository-Hilfsskripte –
beispielsweise die Modulmatrix, End-to-End-Flows und den neuen Layout-Validator.
Die laufzeitrelevanten Wrapper leben unter `forensic/tools/` und kapseln den
Zugriff auf optionale Drittanbieter-Werkzeuge.

## Tool-Wrapper (Guarded)

| Wrapper | Primäre Binaries/Module | Beispiel-Check | Hinweise |
|---------|--------------------------|----------------|----------|
| sleuthkit | `tsk_version`, `mmls`, `fls` | `mmls -V` | Read-only Partition- & Dateisichten; Dry-Run verfügbar |
| plaso | `log2timeline.py`, `psort.py` | `log2timeline.py --version` | Keine produktiven Runs im CI; Wrapper liefert Guard-Hinweise |
| volatility | `volatility3`, `vol`, `python3 -m volatility3` | `volatility3 --version` | Optionales Extra; Wrapper zeigt pslist-Hilfe statt Dumps |
| yara | `yara` | `yara --version` | Scans nur mit `allow_execution=True`, sonst Dry-Run |
| bulk_extractor | `bulk_extractor` | `bulk_extractor -V` | Versionscheck; keine Analyse-Läufe im CI |
| autopsy | `autopsy`, `autopsy64.exe` | n/a | GUI-Hinweis statt automatischer Ausführung |

## Ergänzende Hinweise

- `forensic/core/` bildet das Herzstück (Framework, Module-Basis, Chain of Custody).
- `forensic/modules/` gliedert sich in `acquisition`, `analysis`, `triage` und
  `reporting` – jede Ebene nutzt die neuen Tool-Wrapper über guardete APIs.
- `pipelines/*.yaml` dokumentieren Beispiel-Workflows für orchestrierte Abläufe.
- Der Befehl `python tools/validate_project_layout.py` prüft die Mindeststruktur
  und läuft automatisch im CI-Workflow.
- Weitere Dokumente (`LEGACY.md`, `MIGRATION_GUIDE.md…`) verbleiben zur
  Kontextualisierung der v1→v2 Migration.

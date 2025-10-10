<!-- AUTODOC:BEGIN -->
---
title: "Indicator of Compromise Hunting"
description: "Copy-&-Paste-Workflow zum Abgleich von Artefakten gegen interne IoC-Listen."
---

# Copy & Paste Workflow
## IoC-Datei vorbereiten
```bash
cat > ~/cases/iocs/custom.json <<'EOF
[
  {
    "type": "hash",
    "value": "1234567890abcdef",
    "tags": ["demo"],
    "source": "Internal Test"
  }
]
EOF
```

Legt eine deterministische JSON-Datei im Workspace an.

## Timeline-Ergebnis als Input kopieren
```bash
cp cases/net_timeline/analysis/timeline/timeline.csv cases/net_timeline/analysis/timeline/ioc_input.csv
```

Verwendet vorhandene Timeline-Ausgabe als Datenbasis.

## (Geplantes) IoC-Modul im Dry-Run
```bash
forensic-cli --workspace ~/cases modules run ioc_scanning --case net_timeline --param input=analysis/timeline/ioc_input.csv --param ioc_file=../../iocs/custom.json --dry-run
```

Zeigt, welche Regeln angewendet würden, sobald das Modul verfügbar ist.

## Erwartete Ausgabe (zukünftig)
```text
analysis/ioc/matches.json -> Enthält Trefferliste mit Hash, Pfad, Quelle
```

Bis zur Finalisierung vermerkt das Modul einen TODO-Hinweis im Provenienzlog.

## Erwartete Artefakte
- `cases/net_timeline/analysis/timeline/ioc_input.csv`
- `cases/net_timeline/meta/provenance.jsonl` (Dry-Run-Eintrag `ioc_scanning`)

## Guard-Hinweise
- Verwenden Sie immer zuerst `--dry-run`, bevor Sie schreibende Aktionen bestätigen.
- Prüfen Sie `meta/provenance.jsonl`, um alle Parameter- und Toolquellen zu dokumentieren.

<!-- AUTODOC:END -->

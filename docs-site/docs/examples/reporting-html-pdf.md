<!-- AUTODOC:BEGIN -->
---
title: "Reporting nach HTML und PDF"
description: "Wie man HTML-Reports erzeugt und optional PDF rendert, inklusive Guard-Hinweisen."
---

# Copy & Paste Workflow
## HTML-Report erstellen
```bash
forensic-cli --workspace ~/cases report generate --case net_timeline --fmt html --out ~/cases/net_timeline/reports/net_timeline.html
```

Erzeugt HTML-Report im Case-Ordner. Hash & Pfad werden protokolliert.

## PDF-Verfügbarkeit prüfen
```bash
forensic-cli --workspace ~/cases report generate --case net_timeline --fmt pdf --out ~/cases/net_timeline/reports/net_timeline.pdf --dry-run
```

Dry-Run prüft wkhtmltopdf/WeasyPrint und schreibt Hinweis in Provenienz.

## PDF exportieren (optional)
```bash
forensic-cli --workspace ~/cases report generate --case net_timeline --fmt pdf --out ~/cases/net_timeline/reports/net_timeline.pdf
```

Nur durchführen, wenn die Guard-Prüfung erfolgreich war.

## Artefakte verifizieren
```bash
sha256sum ~/cases/net_timeline/reports/net_timeline.*
cat ~/cases/net_timeline/meta/chain_of_custody.jsonl
```

Hashwerte und Chain-of-Custody-Einträge bestätigen den Export.

## Erwartete Artefakte
- `cases/net_timeline/reports/net_timeline.html`
- `cases/net_timeline/reports/net_timeline.pdf` (optional)
- `cases/net_timeline/meta/chain_of_custody.jsonl`

## Guard-Hinweise
- Verwenden Sie immer zuerst `--dry-run`, bevor Sie schreibende Aktionen bestätigen.
- Prüfen Sie `meta/provenance.jsonl`, um alle Parameter- und Toolquellen zu dokumentieren.

<!-- AUTODOC:END -->

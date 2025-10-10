<!-- AUTODOC:BEGIN -->
---
title: "Minimaler End-to-End Durchlauf"
description: "Kleinster reproduzierbarer Workflow von der Fallanlage bis zum Report-Dry-Run."
---

# Copy & Paste Workflow
## Setup
```bash
forensic-cli --workspace ~/cases diagnostics --summary
forensic-cli --workspace ~/cases case create --name mini_case --description "Minimal E2E"
```

Erzeugt Workspace-Logs und legt den Case an.

## Evidence registrieren
```bash
forensic-cli --workspace ~/cases evidence add --case mini_case --path ~/fixtures/disk01.E01 --type disk
```

Fügt ein vorhandenes Image hinzu (Hash wird automatisch berechnet).

## Module im Dry-Run
```bash
forensic-cli --workspace ~/cases modules run filesystem_analysis --case mini_case --param image=evidence/disk01.E01 --dry-run
```

Verifiziert Tooling ohne das Image zu verändern.

## Report vorbereiten
```bash
forensic-cli --workspace ~/cases report generate --case mini_case --fmt html --dry-run
```

Report-Generator prüft Templates und schreibt Plan in `meta/provenance.jsonl`.

## Erwartete Artefakte
- `cases/mini_case/meta/provenance.jsonl`
- `cases/mini_case/logs/modules/filesystem_analysis-*.log` (nur nach echter Ausführung)
- `cases/mini_case/reports/` (nach deaktiviertem Dry-Run)

## Guard-Hinweise
- Verwenden Sie immer zuerst `--dry-run`, bevor Sie schreibende Aktionen bestätigen.
- Prüfen Sie `meta/provenance.jsonl`, um alle Parameter- und Toolquellen zu dokumentieren.

<!-- AUTODOC:END -->

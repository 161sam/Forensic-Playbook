<!-- AUTODOC:BEGIN -->
---
title: "Quick Triage auf Linux-Hosts"
description: "Schneller Read-Only-Überblick mittels Triage- und Diagnostics-Modulen."
---

# Überblick

Dieses Tutorial richtet sich an Incident-Responder, die ohne Root-Zugriff einen deterministischen Überblick über einen Linux-Host benötigen. Alle Befehle laufen im Dry-Run oder arbeiten read-only.

## Voraussetzungen
- Kali/Ubuntu Host mit installiertem Forensic-Playbook (`pip install -e .`).
- Zugriff auf das Repository und die Konfiguration `config/modules/triage/*.yaml`.
- Standardbenutzer mit sudo-Rechten (nur falls spätere Module Root benötigen).

## Schritt-für-Schritt
### Workspace vorbereiten
```bash
forensic-cli --workspace ~/cases diagnostics --summary
forensic-cli --workspace ~/cases case create --name triage_demo --description "Quick triage" --investigator "Analyst"
```

Die Diagnostics-Ausgabe dokumentiert verfügbare Module, Guards und fehlende Extras (Log: `~/cases/logs/diagnostics.log`).

### Systeminformationen im Dry-Run prüfen
```bash
forensic-cli --workspace ~/cases modules run system_info --case triage_demo --dry-run
```

Der Dry-Run schreibt `meta/provenance.jsonl` und listet geplante Dateien (`triage/system_info/system_info.json`).

### Systeminformationen erfassen
```bash
forensic-cli --workspace ~/cases modules run system_info --case triage_demo
```

Erwartete Artefakte: `cases/triage_demo/triage/system_info/system_info.json` und Markdown-Zusammenfassung. Hashes stehen im `meta/chain_of_custody.jsonl`.

### Quick Triage Profil "extended"
```bash
forensic-cli --workspace ~/cases modules run quick_triage --case triage_demo --param profile=extended
```

Es entstehen `triage/quick/extended/*.json` plus Logs in `logs/modules/quick_triage-<timestamp>.log`.

### Persistenz prüfen (Dry-Run + Ausführung)
```bash
forensic-cli --workspace ~/cases modules run persistence --case triage_demo --dry-run
forensic-cli --workspace ~/cases modules run persistence --case triage_demo
```

Die CSV-Datei `triage/persistence/persistence.csv` enthält Pfade, Hashes und Zeitstempel. Dry-Run protokolliert fehlende Verzeichnisse als Warnung.

## Erwartete Artefakte
- `cases/triage_demo/triage/system_info/system_info.json`
- `cases/triage_demo/triage/quick/extended/*.json`
- `cases/triage_demo/triage/persistence/persistence.csv`
- `cases/triage_demo/meta/provenance.jsonl` (mit allen Schritten)

## Weiterführende Links
- [System Info](/modules/system-info)
- [Quick Triage](/modules/quick-triage)

## Chain-of-Custody Hinweise
- Alle Befehle protokollieren Parameter und Hashes in `meta/provenance.jsonl`. Bewahren Sie Dry-Run-Protokolle gemeinsam mit den Artefakten auf.
- Verwenden Sie `forensic-cli diagnostics --summary` nach jedem Schritt erneut, wenn zusätzliche Module aktiviert werden.

<!-- AUTODOC:END -->

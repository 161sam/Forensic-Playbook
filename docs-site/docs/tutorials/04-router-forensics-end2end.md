<!-- AUTODOC:BEGIN -->
---
title: "Router Forensics End-to-End"
description: "Kompletter Workflow von der Umgebung bis zum Markdown-Report."
---

# Überblick

Der Router-Workflow kombiniert Environment-Setup, Capture-Plan, Extraktion, Manifest und Zusammenfassung. Jeder Abschnitt startet mit einem Dry-Run und verweist auf die Chain-of-Custody-Dateien.

## Voraussetzungen
- Router-Zugriff (SSH oder USB-Dump) in einer Testumgebung.
- Forensic-Playbook installiert, Router-Profile konfiguriert (`config/modules/router/*.yaml`).
- Sudo-Rechte für lokale Captures.

## Schritt-für-Schritt
### Umgebung planen
```bash
forensic-cli router env init --root ~/cases/router_demo --dry-run
```

Dry-Run bestätigt Verzeichnisstruktur und schreibt `router_env_plan.json`.

### Umgebung anlegen
```bash
forensic-cli router env init --root ~/cases/router_demo --dry-run=false
```

Erstellt Ordner & Logs (`~/cases/router_demo/logs/router_env-*.log`).

### Capture vorbereiten
```bash
forensic-cli router capture plan --root ~/cases/router_demo --if eth1 --bpf "not port 22" --duration 180 --dry-run
```

Speichert `capture_plan.json` in `~/cases/router_demo/manifests/`.

### Capture ausführen
```bash
sudo forensic-cli router capture run --root ~/cases/router_demo --if eth1 --bpf "not port 22" --duration 180 --enable-live
```

PCAP landet unter `captures/<timestamp>/`. Chain-of-Custody aktualisiert `meta/provenance.jsonl`.

### Dump extrahieren
```bash
forensic-cli router extract --input ~/router_dumps/ui_bundle.tar.gz --out ~/cases/router_demo/extract
```

Extrahiert UI/Config-Dateien, Hashes im `extract_manifest.json`.

### Manifest erstellen
```bash
forensic-cli router manifest write --source ~/cases/router_demo/extract --out ~/cases/router_demo/manifest.json
```

Inventarisierung mit Hashes & Dateigrößen.

### Markdown-Report generieren
```bash
forensic-cli router summarize --in ~/cases/router_demo/extract --out ~/cases/router_demo/router_summary.md
```

Report referenziert PCAP-Hashes und manifestierte Artefakte.

## Erwartete Artefakte
- `~/cases/router_demo/captures/<timestamp>/*.pcap`
- `~/cases/router_demo/extract/*`
- `~/cases/router_demo/manifest.json`
- `~/cases/router_demo/router_summary.md`

## Weiterführende Links
- [Capture](../router/capture.md)
- [Reporting Html Pdf](../examples/reporting-html-pdf.md)

## Chain-of-Custody Hinweise
- Alle Befehle protokollieren Parameter und Hashes in `meta/provenance.jsonl`. Bewahren Sie Dry-Run-Protokolle gemeinsam mit den Artefakten auf.
- Verwenden Sie `forensic-cli diagnostics --summary` nach jedem Schritt erneut, wenn zusätzliche Module aktiviert werden.

<!-- AUTODOC:END -->

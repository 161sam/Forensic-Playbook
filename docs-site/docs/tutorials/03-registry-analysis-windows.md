<!-- AUTODOC:BEGIN -->
---
title: "Windows Registry Analyse"
description: "Analyse extrahierter Registry-Hives mit Guarded-Checks und optionalem RegRipper."
---

# Überblick

Dieser Leitfaden nutzt ein offline gemountetes Windows-System (E01 oder Dateibundle) und demonstriert, wie das Registry-Modul Dry-Run und Ausführung dokumentiert.

## Voraussetzungen
- Extrahierte Registry-Hives in einem lokalen Ordner (z. B. `~/evidence/win10_mount`).
- Optional: RegRipper installiert (`rip.pl`).
- Forensic-Playbook Umgebung mit Zugriff auf den Mount.

## Schritt-für-Schritt
### Case anlegen und Mount verlinken
```bash
forensic-cli --workspace ~/cases case create --name registry_demo --description "Windows Registry"
ln -s ~/evidence/win10_mount ~/cases/cases/registry_demo/evidence/win10_mount
```

Symbolischer Link stellt sicher, dass der Pfad im Case verfügbar ist (keine Kopie).

### Dry-Run mit Toolprüfung
```bash
forensic-cli --workspace ~/cases modules run registry_analysis --case registry_demo --param target=evidence/win10_mount --dry-run
```

Bei fehlendem RegRipper wird ein Hinweis protokolliert (`missing_tools`). Die geplante Hiveliste erscheint in `meta/provenance.jsonl`.

### Registry Analyse ausführen
```bash
forensic-cli --workspace ~/cases modules run registry_analysis --case registry_demo --param target=evidence/win10_mount --param regripper=true
```

Ausgabe: `analysis/registry/registry.json`, Benutzeraktivitätsberichte und `logs/modules/registry_analysis-*.log`.

### Persistenzbefunde evaluieren
```bash
cat ~/cases/cases/registry_demo/analysis/registry/registry.json | jq 'select(.type=="persistence_mechanisms")'
```

Mit `jq` lassen sich kritische Einträge extrahieren (Hash + Registry-Pfad).

## Erwartete Artefakte
- `cases/registry_demo/analysis/registry/registry.json`
- `cases/registry_demo/logs/modules/registry_analysis-*.log`
- `cases/registry_demo/meta/chain_of_custody.jsonl`

## Weiterführende Links
- [Registry](../modules/registry.md)
- [Persistence](../modules/persistence.md)

## Chain-of-Custody Hinweise
- Alle Befehle protokollieren Parameter und Hashes in `meta/provenance.jsonl`. Bewahren Sie Dry-Run-Protokolle gemeinsam mit den Artefakten auf.
- Verwenden Sie `forensic-cli diagnostics --summary` nach jedem Schritt erneut, wenn zusätzliche Module aktiviert werden.

<!-- AUTODOC:END -->

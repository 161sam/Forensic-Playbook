# Forensic-Playbook – Architekturüberblick

Die Architektur folgt einem klaren Layering-Modell. Jedes Layer fokussiert sich
auf eine definierte Aufgabe und ist durch Guard-Prinzipien abgesichert, damit
CI- und Entwicklungsläufe deterministisch bleiben.

```text
CLI / Pipelines
        │
        ▼
forensic.core ──→ forensic.modules ──→ forensic.tools
        ▲                │                │
        │                ▼                │
        └────────── forensic.utils ◀──────┘
```

## Layer

### forensic.core
- Framework-Lebenszyklus (Cases, Evidence, Pipelines).
- Basisklassen für Module inkl. Guard-Hooks (`validate_params`, `tool_versions`).
- Konfigurations- und Logging-Subsystem (`config.py`, `logger.py`).

### forensic.modules
- Fachliche Implementierungen für Akquise, Analyse, Triage und Reporting.
- Jeder Modultyp nutzt Guard-Checks bevor externe Tools aufgerufen werden.
- Module berichten ihre Tool-Verfügbarkeit über `tool_versions()` und speisen
  diese Informationen in Diagnostik sowie Provenienzprotokolle ein.

### forensic.tools (neu)
- Leichtgewichtige Wrapper für externe Tools (Sleuthkit, Plaso, Volatility,
  YARA, Bulk Extractor, Autopsy).
- Gemeinsames Interface: `available()`, `version()`, `requirements()`,
  `capabilities()` sowie `run_*`-Helfer mit Dry-Run-Unterstützung.
- Kein destruktiver Zugriff – alle Befehle laufen read-only oder liefern einen
  Command-Preview.

### forensic.utils
- Allgemeine Helfer (`cmd`, `hashing`, `io`, `paths`, `timefmt`).
- Wird von Core und Modulen genutzt, bleibt aber frei von Tool-spezifischer
  Logik.

### CLI & Pipelines
- `forensic.cli` orchestriert das Framework, führt Diagnostik aus und publiziert
  Status-Events.
- YAML-Pipelines (`pipelines/*.yaml`) definieren Modul-Ketten und nutzen dieselbe
  Guard-Logik wie der CLI-Einstiegspunkt.

## Guard-Prinzipien

1. **Detect statt Fail:** fehlende Tools führen zu freundlichen Hinweisen statt
   Exceptions. Module liefern strukturierte Fehlerobjekte, die CLI und Tests
   auswerten können.
2. **Dry-Run first:** alle Wrapper akzeptieren `dry_run`, Module spiegeln
   geplante Befehle, bevor echte Aktionen erfolgen.
3. **Read-only Default:** standardmäßig werden nur lesende Operationen
   ausgeführt. Erweiterungen, die schreibende Aktionen benötigen, müssen explizit
   aktiviert werden (z. B. `--enable-live-capture`).
4. **Deterministische Tests:** Wrapper und Module werden in der Test-Suite
   gemockt, damit CI-Läufe ohne externe Tools reproduzierbar bleiben.

## Datenflüsse

1. **CLI/Pipeline → Core:** Benutzerbefehle erzeugen Cases, laden Evidence und
   starten Module.
2. **Core → Module:** Module erhalten validierte Parameter, führen Guard-Checks
   aus und orchestrieren externe Tools über `forensic.tools`.
3. **Module → Tools:** Wrapper bauen sichere Kommandos, führen sie (oder
   Dry-Runs) aus und liefern Rückgabecodes/Stdout/Stderr an die Module.
4. **Module → Core:** Ergebnisse (`ModuleResult`) werden inklusive Metadaten,
   Findings und Tool-Versionen zurückgegeben.
5. **Core → CLI/Reports:** Das Framework schreibt Artefakte, aktualisiert die
   Chain-of-Custody und stellt Daten für Reportgeneratoren bereit.

Diese Struktur ermöglicht eine schrittweise Erweiterung: neue Module binden
Wrapper ein, ohne bestehende Guards zu umgehen. Gleichzeitig bleiben
Repository-Hilfsskripte (`tools/`) unabhängig vom Runtime-Paket.

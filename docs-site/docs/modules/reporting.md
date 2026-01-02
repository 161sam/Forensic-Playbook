<!-- AUTODOC:BEGIN -->
---
title: "Reporting Modules"
description: "Deterministic report generation and artefact exports."
---

# Übersicht

Die Reporting-Schicht fasst Analyseergebnisse zusammen und erstellt weitergabefähige Artefakte. Alle Kommandos respektieren Dry-Run, führen Tool-Prüfungen durch und schreiben Hashes/Metadaten in Chain-of-Custody.

## Modulmatrix

| Modul | Zweck | Schlüsselparameter | Guard & Extras | Outputs |
| --- | --- | --- | --- | --- |
| `generator` | HTML/PDF-Report aus Case-Daten | `case`, `fmt` (`html`, `pdf`), `template`, `out`, `include_sections` | Optional Extra `report_pdf` (`weasyprint`/`wkhtmltopdf`) | HTML/PDF unter `cases/<case>/reports/`, `report_meta.json`, Hashdateien |
| `exporter` | Strukturierten JSON/Markdown-Export erzeugen | `case`, `fmt` (`json`, `markdown`), `out`, `scope` | Keine Zusatztools; nutzt Jinja2 und Core-Serialiser | JSON/MD unter `cases/<case>/reports/exports/`, Log `report_exporter-*.log` |

## Generator (`report.generator`)

- **Zweck:** Erstellt den konsolidierten Fallreport inklusive Chain-of-Custody, Module-Befunde und optional PDF-Rendering.
- **Parameter:** `fmt` (Standard `html`), `template` (Default `default.html.j2`), `out`, `include_sections` (Liste), `dry_run`.
- **Guardrails:** Prüft Template-Pfad, Schreibrechte und PDF-Toolchain. Ohne PDF-Extras → `status="warning"` + Hinweis `Install forensic-playbook[report_pdf]`.
- **Outputs:**
  ```json
  {
    "report_path": "cases/demo_case/reports/demo_case.html",
    "hash_sha256": "...",
    "sections": ["summary", "timeline", "indicators"]
  }
  ```
  Zusätzlich `report_meta.json` (Parameterquellen, Template-Version) und Hash-Datei.

## Exporter (`report.exporter`)

- **Zweck:** Liefert fokussierte Datenexporte (z. B. Indicators, Timeline) für SOC/Ticketing.
- **Parameter:** `fmt` (`json`, `markdown`), `scope` (`summary`, `indicators`, `timeline`), `out`, `case`, `dry_run`.
- **Guardrails:** Prüft Scope-Werte gegen Whitelist, stellt sicher, dass Zielordner innerhalb des Workspaces liegt.
- **Outputs:** JSON/Markdown-Datei mit Schema `{ "case": "demo_case", "artifacts": [...], "indicators": [...] }`. Hash-Datei optional (`--param include_hashes=true`). Logs unter `logs/modules/report_exporter-*.log`.

Weitere Hinweise zu Workflows und PDF-Optionen: [User Guide](../guides/user-guide.md#3-berichtserstellung) und [examples/reporting-html-pdf.md](../examples/reporting-html-pdf.md). Ergänzend: [Acquisition Modules](acquisition.md), [Analysis Modules](analysis.md), [Triage Modules](triage.md) und [Router Modules](router.md).
<!-- AUTODOC:END -->

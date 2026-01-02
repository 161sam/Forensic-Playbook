<!-- AUTODOC:BEGIN -->
---
title: "Router Modules"
description: "Guarded router forensics workflow (env, capture, extract, manifest, summarize, pipeline)."
---

# Übersicht

Die Router-Suite ersetzt Legacy-Skripte durch Guarded-Python-Module. Alle Kommandos verlangen Dry-Run-Bestätigung und halten die Konfigurationsreihenfolge **CLI > Case-YAML > Defaults** ein. Logs landen parallel im Case (`cases/<case>/logs/router/`) und global (`router/logs/`).

## Modulmatrix

| Modul | Zweck | Schlüsselparameter | Guard & Tools | Outputs |
| --- | --- | --- | --- | --- |
| `env` | Arbeitsumgebung vorbereiten (Verzeichnisse, Profile) | `root`, `profile`, `layout`, `dry_run` | Validiert Workspace-Pfade, keine Root-Pflicht | Verzeichnisstruktur unter `cases/<case>/router/`, `env_plan.json` |
| `capture` | Passives Netz-Capture auf Router/Monitor-Port | `interface`, `bpf`, `duration`, `count`, `enable_live_capture`, `tool` | Root + Zustimmung (`--enable-live-capture`), Tools `tcpdump`/`dumpcap` | PCAP `router/capture/<timestamp>.pcap`, Hashdatei, Metadata-JSON |
| `extract` | Entpacken & Normalisieren von Router-Dumps | `source`, `out`, `include_patterns`, `exclude_patterns` | Prüft Archivformate (`tar`, `zip`), read-only | Extrahierte JSON/TXT-Dateien in `router/extract/`, `extract_manifest.json` |
| `manifest` | Evidenzmanifest & Hashes erstellen | `source`, `out`, `hash_algorithm`, `case` | Hashlib (`sha256`, `sha1`), Leserechte erforderlich | `manifest.json`, `hashes.json`, Chain-of-Custody-Eintrag |
| `summarize` | Markdown/JSON-Zusammenfassung der Extrakte | `source`, `out`, `template`, `include_sections` | Jinja2-Templates, optional benutzerdefiniert | Markdown `summary.md`, JSON `summary.json` |
| `pipeline` | Orchestriert env→capture→extract→manifest→summarize | `plan`, `stages`, `dry_run`, `case` | Validiert Stage-Definitionen und Flags (`ack_live`) | Pipeline-Protokoll `router/pipeline/<timestamp>/pipeline.json`, stage logs |

## Environment (`router.env`)

- **Zweck:** Erstellt deterministische Router-Workspace-Struktur (Input, capture, extract, reports).
- **Parameter:** `root` (Default `cases/<case>/router`), `profile` (z. B. `default`, `lab`), `layout` (YAML-Datei), `dry_run`.
- **Guardrails:** Prüft, ob Zielpfad im Workspace liegt und bereits existierende Ordner nicht überschrieben werden. Dry-Run schreibt Plan nach `env_plan.json`.
- **Outputs:** Verzeichnisse plus JSON mit Schema `{ "created": [...], "skipped": [...] }`.

## Capture (`router.capture`)

- **Zweck:** Startet kontrollierte Router-Captures (Mirror-Port oder SSH-Bounce).
- **Parameter:** `interface`, `duration`, `bpf`, `count`, `enable_live_capture`, `tool` (`tcpdump`/`dumpcap`), `out`.
- **Guardrails:** Ohne `--enable-live-capture` -> `status="skipped"`. Prüft Tool-Verfügbarkeit, legt Kommandozeile offen (`metadata.command`).
- **Outputs:** PCAP + `.sha256`, metadata JSON (`command`, `interface`, `duration`). Logs `router_capture-*.log`.

## Extract (`router.extract`)

- **Zweck:** Extrahiert Web-UI-Backups, Konfigurationen oder Tar-Archive in analysierbare JSON/TXT.
- **Parameter:** `source` (Archiv/Ordner), `out`, `include_patterns`, `exclude_patterns`, `normalise_timestamps`.
- **Guardrails:** Verifiziert Quelle, verbietet Schreibzugriffe außerhalb des Zielordners, protokolliert normalisierte Dateien.
- **Outputs:** Extrahierte Dateien unter `router/extract/<slug>/`, `extract_manifest.json` mit Feldern `files[]`, `sha256`.

## Manifest (`router.manifest`)

- **Zweck:** Erstellt Evidence-Manifest mit Hashes, Größen, Kategorien.
- **Parameter:** `source`, `out`, `hash_algorithm` (`sha256` Standard), `case`, `dry_run`.
- **Guardrails:** Prüft, dass `source` innerhalb des Router-Workspaces liegt. Dry-Run gibt Plan (`metadata.preview[]`).
- **Outputs:** `manifest.json` (Schema `{ "files": [{"path": "...", "sha256": "..."}] }`) und optional `manifest.csv`. Chain-of-Custody-Logeintrag verweist auf Hashdatei.

## Summarize (`router.summarize`)

- **Zweck:** Aggregiert Extrakte in Markdown/JSON für schnelle Übergabe.
- **Parameter:** `source`, `out`, `template` (`default.md.j2`), `include_sections`, `dry_run`.
- **Guardrails:** Prüft Template, listet verfügbare Abschnitte (`http_logs`, `dns`, `alerts`). Dry-Run liefert `summary_plan.json`.
- **Outputs:** Markdown-Report `summary.md`, optional JSON `summary.json` mit `sections[].items`.

## Pipeline (`router.pipeline`)

- **Zweck:** Führt definierte Router-Stages sequentiell aus (z. B. env→capture→extract→manifest→summarize).
- **Parameter:** `plan` (YAML mit Stages), `stages` (Override-Liste), `ack_live` (bool für Live-Schritte), `dry_run`.
- **Guardrails:** Analysiert Plan, verweigert Live-Stages ohne `ack_live=true`. Jeder Stage-Run wird protokolliert (`pipeline.json` mit `steps[]`).
- **Outputs:** Pipeline-Ordner `router/pipeline/<timestamp>/` mit Stage-Logs, `pipeline.json` (Status, Artefakte, Parameterquellen).

Weitere Beispiele: [Router Quickstart im User Guide](../guides/user-guide.md#4-router-suite-quickstart) und das [Router End-to-End Tutorial](../tutorials/04-router-forensics-end2end.md). Für vorgelagerte Schritte siehe [Acquisition Modules](acquisition.md) und [Analysis Modules](analysis.md); Reporting erfolgt über [Reporting Modules](reporting.md).
<!-- AUTODOC:END -->

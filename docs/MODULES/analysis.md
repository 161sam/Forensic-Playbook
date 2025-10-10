<!-- AUTODOC:BEGIN -->
---
title: "Analysis Modules"
description: "Read-only artefact analysis for filesystem, memory, network, registry, malware and timeline."
---

# Übersicht

Analysis-Module arbeiten auf zuvor erworbener Evidenz oder synthetischen JSON-Fallbacks. Sie verändern Quellen nicht, protokollieren alle Schritte im Provenienz-Stream und markieren fehlende Tools als Guard-Warnung (`status="skipped"`).

## Modulmatrix

| Modul | Zweck | Schlüsselparameter | Guard & Extras | Outputs |
| --- | --- | --- | --- | --- |
| `filesystem` | Sleuthkit-basierte Dateisystemanalyse | `image`, `partition`, `include_deleted`, `compute_hashes` | Tools `fls`, `mmls`, `icat`; optional Root für Loopback-Mounts | JSON-Bericht `analysis/filesystem/report.json`, Artefaktliste, Log `filesystem-*.log` |
| `memory` | Volatility3/2 Analyse eines Dumps | `image`, `profile`, `plugins`, `triage_only` | Optional Extra `memory`, Tools `volatility3`, `python3` | JSON/CSV in `analysis/memory/`, Findings (`plugins`, `warnings`) |
| `network` | PCAP/JSON-Flussauswertung | `pcap` oder `pcap_json`, `case_label` | Optional Extra `pcap` (`scapy`, `pyshark`); JSON-Fallback eingebaut | `analysis/network/network.json`, `flows.csv`, Log `network-*.log` |
| `registry` | Windows-Registry-Parsing & Heuristiken | `hive_path`, `profiles`, `include_deleted` | Tools `reglookup`, optional `rip.pl` | JSON `analysis/registry/report.json`, Hashliste |
| `timeline` | Ereigniskorrelation mit Plaso/Sleuthkit | `source`, `format`, `type`, `timezone`, `start_date`, `end_date` | Tools `log2timeline.py`, `mactime` (optional extra), fallback CSV | Timeline-Datei (`.csv`, `.jsonl`), Metadata `timeline_meta.json` |
| `malware` | Hashing, YARA-Scans, heuristische Checks | `path`, `yara_rules`, `hash_algorithms` | Optional Extra `yara`; Tools `shasum`/`python` | JSON `analysis/malware/report.json`, Hashes `hashes.json` |

## Filesystem (`filesystem`)

- **Zweck:** Dateisystemstrukturen untersuchen, Partitionen identifizieren und Artefakte extrahieren.
- **Parameter (Auszug):** `image` (Pfad zu RAW/EWF), `partition` (Index), `include_deleted` (bool), `extract_strings`, `compute_hashes`.
- **Guardrails:** Verifiziert, dass das Image existiert und Sleuthkit-Tools verfügbar sind. Fehlende Tools → `status="skipped"` mit Hinweis `Install sleuthkit (fls)`.
- **Outputs:** JSON-Report (`report.json`) enthält `findings` (Partitionen, Dateitypen). Artefakte werden in `metadata["partitions"]`, `metadata["filesystem"]` beschrieben. Logs unter `logs/modules/filesystem-*.log`.

## Memory (`memory`)

- **Zweck:** Volatility-basierte Speicheranalyse (Prozesse, Netzverbindungen, Strings).
- **Parameter:** `image`, optional `profile`, `plugins` (Liste), `triage_only` (Bool), `dry_run`.
- **Guardrails:** Prüft auf `volatility3` (oder `volatility`). Ohne Extra → `status="skipped"` mit `metadata["missing_plugins"]`. Dry-Run liefert Befehlsvorschau.
- **Outputs:** Plugin-spezifische JSON/CSV-Dateien, zentraler Report `analysis/memory/report.json` mit `metadata["selected_plugins"]`, `metadata["warnings"]`.

## Network (`network`)

- **Zweck:** Netzwerkflüsse, DNS-Anfragen und HTTP Requests aus PCAP oder JSON-Fallback.
- **Parameter:** `pcap` (Datei) **oder** `pcap_json` (Pfad oder `-` für STDIN), optional `summary_only`, `case_label`.
- **Guardrails:** Mindestens einer der Parameter muss gesetzt sein. Prüft Datei-Existenz und optional `scapy`/`pyshark`. Fehlen Extras → Hinweis `Install the 'pcap' extra`.
- **Outputs (JSON-Struktur):**
  ```json
  {
    "flows": {"rows": [...], "indicators": {...}},
    "dns": {"queries": [...], "suspicious": [...]},
    "http": {"requests": [...], "indicators": {...}},
    "metadata": {"pcap_json_mode": true, "pcap_sha256": "..."}
  }
  ```
  Zusätzlich `flows.csv` (falls Extras vorhanden) und Logs `logs/modules/network-*.log`.

## Registry (`registry`)

- **Zweck:** Analyse von Windows-Registry-Hives inklusive Persistenz-Heuristiken.
- **Parameter:** `hive_path`, optional `profiles` (`system`, `software`), `include_deleted`, `timeline`.
- **Guardrails:** Prüft Hive-Existenz, optional `reglookup`/`rip.pl`. Fehlende Tools → `status="skipped"` mit Hints.
- **Outputs:** JSON `analysis/registry/report.json` mit `metadata["keys_analyzed"]`, `findings[].type` (z. B. `autorun`, `services`). Hashes werden in `hashes.json` abgelegt.

## Timeline (`timeline`)

- **Zweck:** Vereinheitlichte Timeline aus Plaso (log2timeline) und Sleuthkit (mactime) generieren, inkl. Filter und Zeitzone.
- **Parameter:** `source`, `format` (`csv`, `jsonl`, `body`, `l2tcsv`), `type` (`auto`, `plaso`, `mactime`), `timezone`, `start_date`, `end_date`, `include_mft`, `include_logs`.
- **Guardrails:** Prüft Quellpfad, validiert Tools `log2timeline.py` und `mactime`. Fehlende Tools → `status="skipped"` mit `metadata["missing_tools"]`.
- **Outputs:** Timeline-Datei (`analysis/timeline/timeline.<fmt>`), begleitende `timeline_meta.json` mit `timeline_type`, `timezone`, `entry_count`. Dry-Run dokumentiert geplante Parser.

## Malware (`malware`)

- **Zweck:** Hash-basierte Klassifizierung und YARA/Heuristik-Scans von Binärdateien.
- **Parameter:** `path` (Datei oder Verzeichnis), `hash_algorithms` (Liste), `yara_rules` (Pfad), `max_file_size`.
- **Guardrails:** Prüft Dateiexistenz, optional `yara`. Fehlende YARA-Regeln → Hinweis im Ergebnis.
- **Outputs:** JSON `analysis/malware/report.json` mit `hashes`, `yara_matches`, `suspicious_indicators`. Hash-Dateien (`hashes.json`) pro Artefakt.

Cross-Referenzen: [User Guide](../User-Guide.md) für Workflows, [tutorials/02_network-timeline-walkthrough.md](../tutorials/02_network-timeline-walkthrough.md) für Netzwerk→Timeline und [api/CLI.md](../api/CLI.md) für Befehlsbeispiele. Weitere Kategorien: [Acquisition Modules](acquisition.md), [Triage Modules](triage.md), [Reporting Modules](reporting.md) und [Router Modules](router.md).
<!-- AUTODOC:END -->

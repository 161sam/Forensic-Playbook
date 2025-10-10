<!-- AUTODOC:BEGIN -->
---
title: "Acquisition Modules"
description: "Guarded evidence collection (disk, memory, network, live response)."
---

# Übersicht

Acquisition-Module sammeln Beweise unter strengen Guardrails. Sie arbeiten ausschließlich innerhalb des definierten Workspaces, erzwingen Dry-Run-Previews und protokollieren jede Aktion in Chain-of-Custody und Provenienz.

## Modulmatrix

| Modul | Zweck | Hauptparameter (`--param key=value`) | Guard & Tools | Outputs |
| --- | --- | --- | --- | --- |
| `disk_imaging` | Block-Device imaging als RAW/EWF inkl. Hashing | `source`, `tool`, `hash_algorithm`, `block_size`, `allow_file_source` | Root erforderlich, Tools `dd`, `ddrescue`, `ewfacquire` | `cases/<case>/acq/disk/<slug>.img`/`.E01`, `hashes.json`, Log unter `logs/modules/` |
| `memory_dump` | Live-RAM-Erfassung via AVML | `enable_live_capture`, `hostname` | Dry-Run Pflicht, Linux + `avml`, Root empfohlen | RAW-Dump `cases/<case>/acq/memory/<host>_<timestamp>.raw`, Metadata `.meta.json` |
| `network_capture` | Guarded tcpdump/dumpcap Mitschnitt | `interface`, `bpf`, `duration`, `count`, `tool`, `enable_live_capture` | Root + Netzcap-Abstimmung, Tools `tcpdump`/`dumpcap` | PCAP `cases/<case>/acq/network/<timestamp>.pcap`, `.pcap.sha256`, Metadata-JSON, Log `network_capture-*.log` |
| `live_response` | System-Live-Response (Prozesse, Netzwerk, Persistenz) | `profile`, `collect_logs`, `collect_services` | Root optional, Standard-CLI-Tools (`ps`, `netstat`, `systemctl`) | JSON/Markdown in `cases/<case>/acq/live_response/`, Log `live_response-*.log` |

## Disk Imaging (`disk_imaging`)

- **Zweck:** Gerätesichere Kopie von Blockdevices (physisch oder logisch) inkl. Hash-Prüfung.
- **Parameter (JSON-Auszug):**
  ```json
  {
    "source": "/dev/nvme0n1",
    "tool": "ddrescue",
    "hash_algorithm": "sha256",
    "block_size": "4M",
    "skip_verify": false,
    "allow_file_source": false
  }
  ```
- **Guardrails:** Root-Pflicht, prüft Blockdevice via `stat.S_ISBLK`. Unterstützt nur `dd`, `ddrescue`, `ewfacquire`. Fehlende Tools → `status="failed"` mit Hints.
- **Inputs:** Physisches Device oder Datei (nur mit `allow_file_source=true`).
- **Outputs & Provenienz:** Artefaktdatei unter `cases/<case>/acq/disk/`, Hashliste (`hashes.json`) und Log (`logs/modules/disk_imaging-*.log`). Provenienz hält `parameter_sources` fest.

## Memory Dump (`memory_dump`)

- **Zweck:** Live-RAM-Dump auf Linux-Systemen mittels AVML.
- **Parameter:** `enable_live_capture` (bool, Pflicht für Echtlauf), optional `hostname`, `dry_run`.
- **Guardrails:** Ohne `--enable-live-capture` → `status="skipped"`. Prüft Betriebssystem (nur Linux) und Tool `avml` (`shutil.which`).
- **Outputs:** RAW-Dump + `.meta.json` mit Commandline, Timestamp und Hash. Dry-Run liefert Plan (`findings[].type="dry_run"`).

## Network Capture (`network_capture`)

- **Zweck:** Zeitlich begrenzte Mitschnitte zur späteren Analyse oder Router-Pipeline.
- **Parameter:** `interface` (Default `any`), `bpf` (Default `not port 22`), `duration` (Sekunden), `count`, `tool` (`tcpdump`/`dumpcap`), `enable_live_capture`, `dry_run`.
- **Guardrails:** Fehlender Root oder `enable_live_capture=false` → `status="skipped"`. Validiert Dauer und BPF-Syntax, dokumentiert Parameterquellen.
- **Outputs:** PCAP-Datei, Hash-Datei (`.pcap.sha256`) und begleitendes Metadata-JSON im selben Ordner; Logs unter `logs/modules/network_capture-*.log`. Dry-Run listet erwartete Kommandozeile.

## Live Response (`live_response`)

- **Zweck:** Sammeln laufender Prozess-, Netzwerk- und Persistenzinformationen ohne Systemmanipulation.
- **Parameter:** `profile` (z. B. `default`, `router`), `collect_logs`, `collect_services`, `dry_run`.
- **Guardrails:** Prüft erforderliche Systembefehle (`ps`, `netstat`, `systemctl`). Dry-Run zeigt geplante Sammelkommandos. Kein Root-Zwang, weist aber auf optionale Privilegien hin.
- **Outputs:** JSON-Berichte (`system.json`, `network.json`), Textlisten (services/processes) in `acq/live_response/`. Provenienz-Log dokumentiert jeden Befehl mit Timestamp.

Weitere Details zur Parametrisierung: [config/modules/](../../config/modules/) und die MCP-Adapterbeschreibung in [mcp/codex-workflow.md](../mcp/codex-workflow.md). Siehe außerdem [Analysis Modules](analysis.md), [Triage Modules](triage.md), [Reporting Modules](reporting.md) und [Router Modules](router.md) für nachgelagerte Verarbeitung.
<!-- AUTODOC:END -->

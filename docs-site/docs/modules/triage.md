<!-- AUTODOC:BEGIN -->
---
title: "Triage Modules"
description: "Rapid situational awareness for Linux triage (system info, persistence, quick checks)."
---

# Übersicht

Triage-Module liefern schnelle, reproduzierbare Snapshots ohne Schreibzugriffe. Sie dienen zur Erstbewertung vor tiefen Acquisition-Schritten und stützen sich auf vorhandene Systembefehle.

## Modulmatrix

| Modul | Zweck | Schlüsselparameter | Guard & Tools | Outputs |
| --- | --- | --- | --- | --- |
| `quick_triage` | Durchsucht Mountpunkte nach SUID/SGID, jüngsten Dateien, verdächtigen Pfaden | `target`, `since`, `max_results`, `checks.*`, `dry_run` | Prüft Verzeichniszugriff, nutzt `find`, `stat`, `shlex`; keine Root-Pflicht | CSV `triage/quick_triage/results.csv`, JSON `summary.json`, Log `quick_triage-*.log` |
| `system_info` | System- & Kernelinformationen erfassen | `collect_hardware`, `collect_services`, `dry_run` | Python `platform`, `psutil` (optional), CLI `lsb_release` | JSON `triage/system/info.json`, Markdown-Report |
| `persistence` | Persistence-Artefakte (Autostart, Cron, Services) inventorieren | `scope` (`system`, `user`), `include_disabled`, `dry_run` | Zugriff auf `/etc`, `systemctl`, `crontab`; keine Schreiboperation | JSON `triage/persistence/report.json`, Hashliste |

## Quick Triage (`quick_triage`)

- **Zweck:** Identifiziert auffällige Binärdateien, kürzlich veränderte Artefakte und verdächtige Pfade in einem gemounteten Snapshot.
- **Parameter (Auszug):** `target` (Pfad, Pflicht), `since` (Tage oder ISO8601), `max_results` (int), `checks.suid_sgid.enabled`, `checks.recent_files.include_globs`.
- **Guardrails:** Validiert, dass `target` existiert und ein Verzeichnis ist. Dry-Run listet geplante Checks (`find`-Kommandozeilen) im Ergebnisfeld `findings[].command`.
- **Outputs:** CSV/JSON in `cases/<case>/triage/quick_triage/`. JSON enthält Schema `{ "check": "recent_files", "path": "...", "reason": "mtime" }`.

## System Info (`system_info`)

- **Zweck:** Sammeln grundlegender Systeminformationen (Hardware, OS, Netzwerk), um spätere Artefakte zu kontextualisieren.
- **Parameter:** `collect_hardware`, `collect_network`, `collect_services`, `dry_run`.
- **Guardrails:** Nutzt Python-APIs (`platform`, `socket`). Optionale Tools (`lsb_release`, `systemctl`) werden geprüft; bei Fehlen → Hinweis im Report.
- **Outputs:** JSON `info.json` mit Feldern `hostname`, `kernel`, `network_interfaces`, plus Markdown `info.md`. Logs liegen unter `logs/modules/system_info-*.log`.

## Persistence (`persistence`)

- **Zweck:** Auflisten persistenter Mechanismen (Systemd-Units, Cronjobs, Shell-Profile) für schnelle Erkennungen.
- **Parameter:** `scope` (`system`, `user`, `all`), `include_disabled` (Bool), `include_hashes`, `dry_run`.
- **Guardrails:** Überprüft Zugriffsrechte auf `/etc`, `$HOME`. Fehlende Tools (`systemctl`, `crontab`) werden als Warning protokolliert.
- **Outputs:** JSON `report.json` mit Arrays `autoruns`, `cron`, `services`. Schema-Auszug:
  ```json
  {
    "autoruns": [
      {"path": "/etc/rc.local", "enabled": true, "hash": "..."}
    ],
    "cron": [
      {"user": "root", "schedule": "*/15 * * * *", "command": "/usr/local/bin/task"}
    ]
  }
  ```
  Hashlisten werden optional unter `hashes.json` abgelegt.

Weitere Beispiele finden Sie im [Quick-Triage-Tutorial](../tutorials/01_quick-triage-linux.md) sowie im [Minimalen E2E-Workflow](../examples/minimal-e2e.md). Für weiterführende Verarbeitung siehe [Analysis Modules](analysis.md), [Acquisition Modules](acquisition.md), [Reporting Modules](reporting.md) und [Router Modules](router.md).
<!-- AUTODOC:END -->

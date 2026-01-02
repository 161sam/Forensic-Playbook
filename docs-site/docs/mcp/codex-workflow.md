<!-- AUTODOC:BEGIN -->
---
title: "Codex & MCP Workflow"
description: "How to operate Forensic-Playbook through Codex MCP integrations."
---

# Überblick

Der Codex/MCP-Workflow ergänzt den bestehenden CLI/SDK-Weg um eine automatisierte, prompt-gesteuerte Variante. Beide Workflows greifen auf dieselben Guardrails zu: Dry-Run-first, deterministische Ausgaben und vollständige Provenienz.

| Workflow | Zweck | Primäre Befehle |
| --- | --- | --- |
| **CLI / SDK** | Manuelle Steuerung, Skripting, lokale Automatisierung | `forensic-cli modules run ... --dry-run`, Python-SDK in `docs/api/SDK.md` |
| **Codex + MCP** | Natural-Language-Automation mit Forensic Mode | `forensic-cli codex …`, `forensic-cli mcp …`, Prompts aus [`forensic/mcp/prompts/forensic_mode.txt`](../../forensic/mcp/prompts/forensic_mode.txt) |

### Plan → Confirm → Execute

1. **Plan** – Codex erstellt ausschließlich Dry-Run/Plan-Ausgaben (`--dry-run`, `--plan`). Ergebnis enthält Logpfade, Artefaktvorschau und Guard-Status.
2. **Confirm** – Analyst bestätigt schriftlich (Ticket-ID, Chat-Freigabe) oder über CLI-Flags (`--accept-risk`, `--ack-live`). Ohne Bestätigung bleibt der Status `pending`.
3. **Execute** – Erst nach Bestätigung dürfen Live-Kommandos laufen. Jeder Lauf aktualisiert `meta/provenance.jsonl` und legt Logs unter `<workspace>/codex_logs/` ab.

Verweisen Sie in Prompts explizit auf diese Sequenz (z. B. „Plane erst, warte auf Bestätigung, führe dann aus“), damit Agenten im Forensic Mode bleiben.

## Vorbereitung (Dry-Run-Pipeline)

1. **Workspace festlegen** — z. B. `--workspace /mnt/usb_rw/cases/demo`. Alle Pfade beziehen sich auf diesen Ort.
2. **Diagnose starten** — Guard-Status und fehlende Abhängigkeiten prüfen:
   ```bash
   forensic-cli --workspace /mnt/usb_rw/cases/demo diagnostics --summary
   ```
3. **Codex-Installationsplan prüfen** — nur Plan, keine Änderungen:
   ```bash
   forensic-cli --workspace /mnt/usb_rw/cases/demo codex install --dry-run
   ```
4. **Codex installieren (nach Freigabe)** — erst nach dokumentierter Zustimmung (Confirm-Gate):
   ```bash
   forensic-cli --workspace /mnt/usb_rw/cases/demo codex install --accept-risk
   ```
5. **MCP-Konfiguration verifizieren** — Einstellungen unter `config/mcp/*.yaml` prüfen, Auth-Tokens nie hard-coden.

## Codex-Dienst starten & überwachen

```bash
forensic-cli --workspace /mnt/usb_rw/cases/demo codex start --foreground --dry-run
forensic-cli --workspace /mnt/usb_rw/cases/demo codex start --foreground
```

- Logs landen deterministisch unter `<workspace>/codex_logs/`.
- `--foreground` eignet sich für Debugging; mit `--background` wird der Prozess in kontrollierte Supervisor-Dateien geschrieben.

Statuskontrolle:

```bash
forensic-cli --workspace /mnt/usb_rw/cases/demo codex status --json
forensic-cli --workspace /mnt/usb_rw/cases/demo mcp status --json
```

`codex status` prüft den lokalen Dienst, `mcp status` ergänzt Erreichbarkeit der Kali- und Forensic-Server.

## MCP-Katalog veröffentlichen

```bash
forensic-cli --workspace /mnt/usb_rw/cases/demo mcp expose --json > /mnt/usb_rw/cases/demo/tooling/mcp_catalog.json
```

- Ausgabe ist stabil sortiert (Toolnamen, Kategorien, Argumente).
- Archivieren Sie das JSON zusammen mit Chain-of-Custody-Logs, um Prompt-Sitzungen reproduzierbar zu machen.

## Tools guarded ausführen

```bash
forensic-cli --workspace /mnt/usb_rw/cases/demo mcp run diagnostics.ping --local --json
```

- `--local` nutzt Python-Adapter ohne Netzwerkeinsatz.
- Für potenziell schreibende Tools steht `--dry-run` oder `--plan` bereit; Live-Ausführung erfordert das Flag `--accept-risk` oder eine bestätigte Prompt-Freigabe.

### Beispielablauf (Timeline-Analyse)
1. Analyst sendet Prompt: „Erstelle einen Dry-Run-Plan für `modules.timeline` und verweise auf `analysis/timeline/`.“
2. Codex antwortet mit `forensic-cli modules run timeline --dry-run ...` samt Logpfaden und Verweis auf [`forensic_mode.txt`](../../forensic/mcp/prompts/forensic_mode.txt).
3. Nach Freigabe wiederholt Codex den Befehl ohne `--dry-run`, dokumentiert Artefakte in `meta/provenance.jsonl` und aktualisiert den MCP-Katalog bei Bedarf.

## Fehlersuche & Aufräumen

- `forensic-cli codex status --verbose` zeigt Log-Tail an.
- `forensic-cli mcp run diagnostics.self_test --local --json` prüft Adapter und Registry.
- Nach Abschluss: `forensic-cli codex stop` und Logs nach Chain-of-Custody-Vorgaben archivieren, bevor sie gelöscht werden.
- Archivieren Sie erzeugte `mcp_catalog.json` und Prompt-Protokolle gemeinsam mit `meta/provenance.jsonl`, um Confirm-Gates zu dokumentieren.

<!-- AUTODOC:END -->

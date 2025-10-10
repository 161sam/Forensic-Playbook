<!-- AUTODOC:BEGIN -->
---
title: "Codex & MCP Workflow"
description: "How to operate Forensic-Playbook through Codex MCP integrations."
---

# Überblick

Der Codex-Workflow erweitert die CLI/SDK-Funktionen um einen MCP-Endpunkt. Ziel ist eine deterministische Steuerung durch
Natural-Language-Prompts, ohne Sicherheitsgarantien zu verlieren. Jeder Schritt beginnt mit einem Dry-Run und dokumentiert
Provenienz sowie Logpfade.

## Vorbereitung

1. **Workspace wählen:** Legen Sie ein dediziertes Verzeichnis fest (`--workspace`).
2. **Diagnose ausführen:**
   ```bash
   forensic-cli --workspace ~/cases diagnostics --summary
   ```
   Prüfen Sie Guard-Warnungen und optional installierbare Extras.
3. **Codex-Pakete installieren (Dry-Run zuerst):**
   ```bash
   forensic-cli --workspace ~/cases codex install --dry-run
   forensic-cli --workspace ~/cases codex install
   ```
4. **MCP konfigurieren:** Die standardisierte Konfiguration liegt unter `config/mcp/`. Passen Sie Endpoint, Token und TLS-Optionen
   an, bevor der Dienst gestartet wird.

## MCP-Dienst starten

```bash
forensic-cli --workspace ~/cases codex start --foreground --dry-run
forensic-cli --workspace ~/cases codex start --foreground
```

- `--foreground` erleichtert das Debugging; alternativ steht `--background` zur Verfügung.
- Logs landen unter `<workspace>/codex_logs/` und im allgemeinen Workspace-Log (`logs/`).

Überprüfen Sie den Status:

```bash
forensic-cli --workspace ~/cases codex status
forensic-cli --workspace ~/cases mcp status
```

`codex status` prüft den MCP-Dienst; `mcp status` kontrolliert zusätzlich Adapter und Tool-Katalog.

## Tools veröffentlichen

```bash
forensic-cli --workspace ~/cases mcp expose --json > ~/cases/tooling/mcp_catalog.json
```

- Die JSON-Datei enthält Toolnamen, Guard-Level und Parameterbeschreibungen.
- Bewahren Sie die Datei versionskontrolliert auf, damit Codex-Sessions auf denselben Funktionsumfang zugreifen.

## Tools ausführen

```bash
forensic-cli --workspace ~/cases mcp run --tool diagnostics.ping --local --json
```

- `--local` nutzt den eingebauten Adapter, ohne Netzwerkaufrufe.
- Verwenden Sie `--dry-run`, wenn ein Tool schreibende Aktionen durchführen könnte.

## Prompt-Beispiele

**System-Prompt (Auszug):**
```
Du agierst im Forensic Mode. Führe zuerst einen Dry-Run durch, fasse die geplanten Schritte zusammen und warte auf Freigabe.
Dokumentiere Workspace, Logpfade und Chain-of-Custody-Hinweise.
```

**Benutzer-Prompt:**
```
Plane eine Timeline-Analyse für den Fall `net_timeline`. Führe zunächst einen Dry-Run durch, verweise auf die Artefakte aus dem
Netzwerkmodul und bestätige, dass keine zusätzlichen Tools notwendig sind.
```

**Erwarteter Ablauf:**
1. MCP ruft `forensic-cli modules run timeline --dry-run ...` auf.
2. Der Agent fasst geplante Pfade/Logs zusammen.
3. Nach Freigabe wird der Echtlauf angestoßen, Provenienz aktualisiert und ein Verweis auf `analysis/timeline/` geliefert.

## Fehlersuche

- `forensic-cli codex status --verbose` liefert die letzten Logzeilen des Dienstes.
- `forensic-cli mcp run --tool diagnostics.self_test --json` prüft Adapter-Integrität.
- Prüfen Sie Firewalls/SELinux, falls `status` keine Verbindung herstellen kann.

## Aufräumen

```bash
forensic-cli --workspace ~/cases codex stop
rm -rf ~/cases/codex_logs/*
```

Sichern Sie Tool-Kataloge (`mcp expose`) und Chain-of-Custody-Einträge, bevor Sie Logs löschen.

<!-- AUTODOC:END -->

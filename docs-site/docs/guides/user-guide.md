<!-- AUTODOC:BEGIN -->
---
title: "Forensic-Playbook User Guide"
description: "Operational handbook for analysts using the Forensic-Playbook framework."
---

# Überblick

Der **User Guide** vermittelt Incident-Respondern und Forensik-Analystinnen einen durchgehenden Workflow vom Setup bis zur MCP-Automatisierung. Alle Beispiele folgen den Forensic-Mode-Prinzipien: **Dry-Run zuerst**, Guard-Prüfungen respektieren, Provenienz sichern.

## Installation & Setup

```bash
# Repository klonen und virtuelle Umgebung anlegen
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Optionale Extras (bei Bedarf)
pip install "forensic-playbook[pcap]"      # Netzwerk-Parsing
pip install "forensic-playbook[report_pdf]" # PDF-Export

# Diagnose im Dry-Run (prüft Guard-Status)
forensic-cli diagnostics --summary --dry-run
```

- Unterstützte Plattformen: Kali 2024.x, Ubuntu 22.04 LTS, Debian 12 (Python ≥ 3.10).
- Alle Module schreiben Logs unter `<workspace>/logs/` und Provenienz nach `cases/<case>/meta/`.

### Konfigurations-Priorität

Die Auflösung der Parameter ist strikt determiniert:

1. **CLI-Flags** (`--param key=value`, `--workspace`, `--dry-run`).
2. **Case-spezifische YAMLs** (`cases/<id>/config/**/*.yaml`).
3. **Globale Defaults** (`config/framework.yaml`, `config/modules/*.yaml`).

```bash
forensic-cli --workspace ~/cases modules run network \
    --case demo_case \
    --param pcap_json=cases/demo_case/input/flows.json \
    --dry-run
```

Der endgültige Parameter-Satz wird in `meta/provenance.jsonl` dokumentiert.

### Guards & Dry-Run

Guarded Module prüfen vor der Ausführung Tooling, Privilegien und Pfadgrenzen. Typische Guard-Fehler resultieren in `status="skipped"` statt Exceptions.

```bash
# Guard-Check für ein Modul
forensic-cli diagnostics --modules acquisition.disk_imaging --dry-run

# Dry-Run zeigt geplante Schritte und Zielpfade
forensic-cli modules run disk_imaging \
    --case demo_case \
    --param source=/dev/nvme0n1 \
    --param out=cases/demo_case/acquisition/disk01.E01 \
    --dry-run
```

## Standard-Workflows

### 1. Disk Acquisition

```bash
# Workspace vorbereiten
forensic-cli --workspace ~/cases case create \
    --name demo_case \
    --description "Workstation DFIR Walkthrough"

# Dry-Run planen (keine Schreibzugriffe)
forensic-cli --workspace ~/cases modules run disk_imaging \
    --case demo_case \
    --param source=/dev/nvme0n1 \
    --param out=cases/demo_case/acquisition/disk01.E01 \
    --dry-run

# Nach Freigabe (Root + Flag erforderlich)
sudo forensic-cli --workspace ~/cases modules run disk_imaging \
    --case demo_case \
    --param source=/dev/nvme0n1 \
    --param out=cases/demo_case/acquisition/disk01.E01 \
    --param hash=sha256 \
    --enable-live-capture
```

- Logs: `cases/demo_case/logs/modules/disk_imaging-*.log`
- Hashliste: `cases/demo_case/acquisition/hashes.json`
- Chain-of-Custody: `cases/demo_case/meta/chain_of_custody.jsonl`

### 2. Network → Timeline Analyse (JSON-Fallback)

```bash
# Synth-Flows bereitstellen (keine Binär-Fixtures)
mkdir -p ~/cases/demo_case/input
cat <<'JSON' > ~/cases/demo_case/input/flows.json
{
  "flows": [
    {
      "src": "10.0.0.5", "dst": "10.0.0.2",
      "src_port": 12345, "dst_port": 8080,
      "protocol": "TCP", "packets": 10, "bytes": 5120,
      "start_ts": "2024-01-02T00:00:05Z", "end_ts": "2024-01-02T00:00:10Z"
    }
  ],
  "dns": [
    {"timestamp": "2024-01-02T00:00:00Z", "query": "example.org", "query_type": 1}
  ],
  "http": [
    {
      "timestamp": "2024-01-02T00:00:00Z",
      "method": "GET", "host": "portal.example.org", "uri": "/status",
      "user_agent": "Mozilla/5.0", "indicators": {"encoded_uri": false}
    }
  ]
}
JSON

# Netzwerkmodul planen und ausführen
forensic-cli --workspace ~/cases modules run network \
    --case demo_case \
    --param pcap_json=cases/demo_case/input/flows.json \
    --dry-run
forensic-cli --workspace ~/cases modules run network \
    --case demo_case \
    --param pcap_json=cases/demo_case/input/flows.json

# Timeline auf Basis der Netzwerkbefunde
forensic-cli --workspace ~/cases modules run timeline \
    --case demo_case \
    --param source=cases/demo_case/analysis/network \
    --param format=csv \
    --dry-run
forensic-cli --workspace ~/cases modules run timeline \
    --case demo_case \
    --param source=cases/demo_case/analysis/network \
    --param format=csv
```

Artefakte werden unter `analysis/network/` und `analysis/timeline/` abgelegt. Weitere Details liefert das [Network-Timeline-Tutorial](../tutorials/02-network-timeline-walkthrough.md).

### 3. Berichtserstellung

```bash
# HTML als Standard
forensic-cli --workspace ~/cases report generate \
    --case demo_case \
    --fmt html \
    --out cases/demo_case/reports/demo_case.html \
    --dry-run
forensic-cli --workspace ~/cases report generate \
    --case demo_case \
    --fmt html \
    --out cases/demo_case/reports/demo_case.html

# PDF nur bei installiertem Extra (Dry-Run prüft Renderer)
forensic-cli --workspace ~/cases report generate \
    --case demo_case \
    --fmt pdf \
    --out cases/demo_case/reports/demo_case.pdf \
    --dry-run
```

Hashwerte und Exportpfade landen automatisch im Chain-of-Custody-Protokoll. Für Layoutoptionen siehe [modules/reporting.md](../modules/reporting.md).

### 4. Router-Suite Quickstart

```bash
# Umgebung (Dry-Run prüft Pfade)
forensic-cli router env init \
    --workspace ~/cases \
    --case demo_case \
    --profile default \
    --dry-run

# Extraktion & Manifest (JSON-only Artefakte)
forensic-cli router extract ui \
    --workspace ~/cases \
    --case demo_case \
    --param source=cases/demo_case/router/raw_ui \
    --dry-run
forensic-cli router manifest write \
    --workspace ~/cases \
    --case demo_case \
    --param source=cases/demo_case/router/extract \
    --dry-run

# Analyse & Pipeline
forensic-cli router summarize \
    --workspace ~/cases \
    --case demo_case \
    --param source=cases/demo_case/router/extract \
    --dry-run
forensic-cli router pipeline run \
    --workspace ~/cases \
    --case demo_case \
    --dry-run
```

Die Router-Module spiegeln Legacy-Skripte, protokollieren Schritte nach `logs/router/` und schreiben JSON-Manifeste. Details stehen in [Router Modules](/modules/router).

## MCP & Codex Kurzstart

```bash
# Installation & Dienste (Dry-Run Pflicht)
forensic-cli --workspace ~/cases codex install --dry-run
forensic-cli --workspace ~/cases codex install --accept-risk
forensic-cli --workspace ~/cases codex start --foreground --dry-run
forensic-cli --workspace ~/cases codex start --foreground

# Status prüfen
forensic-cli --workspace ~/cases codex status --json
forensic-cli --workspace ~/cases mcp status --json

# Werkzeugkatalog & Testlauf
forensic-cli --workspace ~/cases mcp expose --json \
    > ~/cases/demo_case/tooling/mcp_catalog.json
forensic-cli --workspace ~/cases mcp run diagnostics.ping \
    --local \
    --json
```

- Logs liegen deterministisch in `<workspace>/codex_logs/`.
- Prompt-Guardrails sind in [mcp/forensic-mode.md](mcp/forensic-mode.md) dokumentiert.
- Der Ablauf „Plan → Confirm → Execute“ ist verpflichtend; Codex führt Live-Schritte nur nach Freigabe aus. Der vollständige Workflow steht in [mcp/codex-workflow.md](mcp/codex-workflow.md).

## Troubleshooting & FAQ

| Symptom | Diagnose (Dry-Run) | Lösung |
| --- | --- | --- |
| Fehlende Tools (`status=skipped`) | `forensic-cli diagnostics --modules <name>` | Fehlende Pakete installieren oder Extras aktivieren (`pip install forensic-playbook[pcap]`). |
| Keine Schreibrechte im Workspace | `forensic-cli --workspace /pfad diagnostics --summary --dry-run` | Pfade auf `/mnt/usb_rw` oder Nutzerverzeichnis legen; Root nur mit Freigabe. |
| PDF-Export schlägt fehl | `forensic-cli report generate ... --fmt pdf --dry-run` | Renderer installieren oder auf HTML zurückfallen; Hinweis im Report beachten. |
| MCP-Status meldet Offline | `forensic-cli codex status --verbose` | Logs unter `<workspace>/codex_logs/` prüfen, Dienst neu starten (`codex stop`, dann `start`). |
| Unklare Parameterquelle | `jq` auf `meta/provenance.jsonl` | Eintrag zeigt Quelle (`cli`, `case_config`, `default`) inkl. Timestamp und Hash. |

**Weitere Fragen**

- *Wie aktualisiere ich das Framework?* — `git pull`, virtuelles Environment aktivieren, `pip install -e .`, danach `forensic-cli diagnostics --summary --dry-run`.
- *Kann ich Module parallel ausführen?* — Ja, sofern Artefaktpfade getrennt sind. Nutzen Sie getrennte Cases oder Workspaces, um Überschneidungen zu vermeiden.
- *Wie teile ich Ergebnisse mit Incident-Response?* — HTML-Report prüfen, optional PDF erzeugen, anschließend `reports/`, `meta/` und relevante Logs (inkl. Hashdateien) archivieren.

---

Weiterführende Ressourcen: [Developer Guide](developer-guide.md), [CLI-Referenz](../api/cli.md), [Modul-Katalog](../modules/analysis.md), [Minimaler E2E-Workflow](../examples/minimal-e2e.md) und das [Network-Timeline-Tutorial](../tutorials/02-network-timeline-walkthrough.md).
<!-- AUTODOC:END -->

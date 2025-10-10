<!-- AUTODOC:BEGIN -->
---
title: "Network-zu-Timeline Walkthrough"
description: "Korrelation eines JSON-basierten Netzwerkbefunds mit dem Timeline-Modul (Dry-Run-first)."
---

# Überblick

Dieses Tutorial führt durch einen typischen Netzwerk→Timeline-Workflow ohne Binär-Fixtures. Wir erzeugen synthetische Flussdaten (JSON), analysieren sie mit dem Netzwerkmodul und leiten anschließend eine Timeline ab.

## Voraussetzungen

- Forensic-Playbook installiert (`pip install -e .`).
- Optionales Extra `pcap` erhöht die Parserqualität, ist aber nicht zwingend (`pip install forensic-playbook[pcap]`).
- Schreibrechte in einem Workspace (`~/cases` oder `/mnt/usb_rw/cases`).

## Schritt 1 – Case vorbereiten

```bash
forensic-cli --workspace ~/cases case create \
    --name net_timeline \
    --description "JSON network flow walkthrough"
```

## Schritt 2 – JSON-Flows erzeugen

```bash
mkdir -p ~/cases/net_timeline/input
cat <<'JSON' > ~/cases/net_timeline/input/flows.json
{
  "flows": [
    {
      "src": "10.0.0.5", "dst": "10.0.0.2",
      "src_port": 12345, "dst_port": 8080,
      "protocol": "TCP", "packets": 10, "bytes": 5120,
      "start_ts": "2024-01-02T00:00:05Z", "end_ts": "2024-01-02T00:00:10Z"
    },
    {
      "src": "10.0.0.1", "dst": "10.0.0.3",
      "src_port": 443, "dst_port": 55555,
      "protocol": "TCP", "packets": 2, "bytes": 1024,
      "start_ts": "2024-01-01T00:00:01Z", "end_ts": "2024-01-01T00:00:02Z"
    }
  ],
  "dns": [
    {"timestamp": "2024-01-02T00:00:00Z", "query": "example.org", "query_type": 1},
    {"timestamp": "2024-01-01T00:00:00Z", "query": "xn--alert-9qa.example", "query_type": 1,
     "heuristics": {"punycode": true}}
  ],
  "http": [
    {
      "timestamp": "2024-01-02T00:00:00Z",
      "method": "GET", "host": "portal.example.org", "uri": "/status",
      "user_agent": "Mozilla/5.0"
    },
    {
      "timestamp": "2024-01-01T00:00:00Z",
      "method": "POST", "host": "api.evil.test", "uri": "/upload",
      "user_agent": "curl/7.88.1",
      "indicators": {"suspicious_user_agent": true}
    }
  ]
}
JSON
```

> **Hinweis:** JSON kann auch via stdin eingespeist werden (`--param pcap_json=-`). Bewahren Sie die Datei unter `input/` auf, damit Provenienz und Hashes dokumentiert werden können.

## Schritt 3 – Netzwerkmodul (Dry-Run & Ausführung)

```bash
# Dry-Run: Parameter und fehlende Extras prüfen
forensic-cli --workspace ~/cases modules run network \
    --case net_timeline \
    --param pcap_json=cases/net_timeline/input/flows.json \
    --dry-run \
    --json

# Ausführung: JSON analysieren, Artefakte schreiben
forensic-cli --workspace ~/cases modules run network \
    --case net_timeline \
    --param pcap_json=cases/net_timeline/input/flows.json
```

Ergebnis: `cases/net_timeline/analysis/network/network.json` (siehe Felder `flows`, `dns`, `http`) und optional `flows.csv` falls Extras aktiv sind. Logs: `logs/modules/network-*.log`.

## Schritt 4 – Timeline planen und erzeugen

```bash
# Dry-Run kontrolliert Pfade und Tool-Verfügbarkeit
forensic-cli --workspace ~/cases modules run timeline \
    --case net_timeline \
    --param source=cases/net_timeline/analysis/network \
    --param format=csv \
    --dry-run

# Ausführung (falls Tools verfügbar)
forensic-cli --workspace ~/cases modules run timeline \
    --case net_timeline \
    --param source=cases/net_timeline/analysis/network \
    --param format=csv
```

Ausgabe: `cases/net_timeline/analysis/timeline/timeline.csv` sowie `timeline_meta.json` (enthält `entry_count`, `timezone`, `source`). Fehlen Plaso/Mactime-Tools, markiert der Guard den Lauf als `skipped` und verweist auf Installationshinweise.

## Schritt 5 – Berichtsauszug erzeugen (optional)

```bash
forensic-cli --workspace ~/cases report generate \
    --case net_timeline \
    --fmt html \
    --out cases/net_timeline/reports/net_timeline.html \
    --dry-run
```

Dadurch werden Timeline- und Netzwerkbefunde im Report geplant. Prüfen Sie `report_meta.json` und `meta/provenance.jsonl` für die Chain-of-Custody.

## Chain-of-Custody Hinweise

- Jede Ausführung erzeugt einen Eintrag in `cases/net_timeline/meta/provenance.jsonl` inklusive Parameterquelle (`cli`, `default`).
- Netzwerk- und Timeline-Module speichern Hashes (`metadata.pcap_json_sha256`, `metadata.timeline_sha256`), sofern anwendbar.
- Bewahren Sie JSON- und CSV-Ausgaben gemeinsam mit den Logs auf, um den Ablauf später nachvollziehen zu können.

Weitere Hintergründe: [Module-Katalog – Analysis](../MODULES/analysis.md) und [CLI-Referenz](../api/CLI.md).
<!-- AUTODOC:END -->

<!-- AUTODOC:BEGIN -->
---
title: "Network-zu-Timeline Walkthrough"
description: "Korrelation eines PCAP mit Timeline-Modul unter Nutzung synthetischer Fixtures."
---

# Überblick

Dieses Tutorial zeigt, wie man einen Netzwerkmitschnitt analysiert und die Ergebnisse in eine forensische Timeline überführt. Alle Schritte laufen zunächst als Dry-Run, danach auf dem bereitgestellten Synth-PCAP.

## Voraussetzungen
- Forensic-Playbook installiert (`pip install -e .`).
- Optional: `pip install forensic-playbook[pcap]` für scapy/pyshark.
- Schreibrechte im Workspace-Verzeichnis (z. B. `~/cases`).

## Schritt-für-Schritt
### Case anlegen und Fixture erzeugen
```bash
forensic-cli --workspace ~/cases case create --name net_timeline --description "PCAP to timeline"
python - <<'PY'
from pathlib import Path
from tests.data.pcap import write_minimal_pcap
workspace = Path("~/cases").expanduser()
pcap = write_minimal_pcap(workspace / "fixtures" / "minimal.pcap")
print(pcappath:=pcap)
PY
```

Der Python-Snippet erstellt `~/cases/fixtures/minimal.pcap` deterministisch (Hash im Terminal notieren).

### Netzwerkmodul Dry-Run
```bash
forensic-cli --workspace ~/cases modules run network --case net_timeline --param source=fixtures/minimal.pcap --dry-run
```

Erwartete Ausgabe: Guard-Log mit Hinweis, ob pcap-Extras fehlen; Plan-Datei im Provenienzlog.

### Netzwerkmodul ausführen
```bash
forensic-cli --workspace ~/cases modules run network --case net_timeline --param source=fixtures/minimal.pcap
```

Artefakte: `cases/net_timeline/analysis/network/network.json` plus optional `flows.csv`. Logs unter `logs/modules/network-*.log`.

### Timeline vorbereiten (Dry-Run)
```bash
forensic-cli --workspace ~/cases modules run timeline --case net_timeline --param source=cases/net_timeline/analysis/network --param format=csv --dry-run
```

Dry-Run bestätigt Pfade und prüft plaso/mactime-Verfügbarkeit.

### Timeline erzeugen
```bash
forensic-cli --workspace ~/cases modules run timeline --case net_timeline --param source=cases/net_timeline/analysis/network --param format=csv
```

Ergebnis: `cases/net_timeline/analysis/timeline/timeline.csv` mit Netzwerkereignissen, referenziert in `meta/provenance.jsonl`.

## Erwartete Artefakte
- `cases/net_timeline/analysis/network/network.json`
- `cases/net_timeline/analysis/timeline/timeline.csv`
- `cases/net_timeline/logs/modules/network-*.log`
- `cases/net_timeline/meta/provenance.jsonl`

## Weiterführende Links
- [Network](../modules/network.md)
- [Timeline](../modules/timeline.md)

## Chain-of-Custody Hinweise
- Alle Befehle protokollieren Parameter und Hashes in `meta/provenance.jsonl`. Bewahren Sie Dry-Run-Protokolle gemeinsam mit den Artefakten auf.
- Verwenden Sie `forensic-cli diagnostics --summary` nach jedem Schritt erneut, wenn zusätzliche Module aktiviert werden.

<!-- AUTODOC:END -->

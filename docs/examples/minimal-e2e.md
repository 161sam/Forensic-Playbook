<!-- AUTODOC:BEGIN -->
---
title: "Minimaler End-to-End Durchlauf"
description: "Kleinster reproduzierbarer Workflow von der Fallanlage bis zum Report-Dry-Run ohne Binär-Fixtures."
---

# Überblick

Dieses Beispiel zeigt einen kompletten, aber leichtgewichtigen Ablauf: Case anlegen, synthetische Artefakte erzeugen, Module im Dry-Run (bzw. JSON-Fallback) ausführen und einen Report vorbereiten. Alle Schritte funktionieren ohne zusätzliche Binärdateien.

## 1. Workspace & Case

```bash
forensic-cli --workspace ~/cases diagnostics --summary --dry-run
forensic-cli --workspace ~/cases case create \
    --name minimal_case \
    --description "Minimal JSON-based walkthrough"
```

## 2. Synthetische Artefakte erstellen

```bash
mkdir -p ~/cases/minimal_case/input
python - <<'PY'
from pathlib import Path
case_root = Path('~/cases/minimal_case').expanduser()
(case_root / 'input').mkdir(parents=True, exist_ok=True)
(case_root / 'input' / 'disk_stub.dd').write_bytes(b'STABLE-STUB')
(case_root / 'input' / 'flows.json').write_text('''{
  "flows": [{
    "src": "10.0.0.5", "dst": "10.0.0.2",
    "src_port": 12345, "dst_port": 8080,
    "protocol": "TCP", "packets": 10, "bytes": 5120,
    "start_ts": "2024-01-02T00:00:05Z", "end_ts": "2024-01-02T00:00:10Z"
  }],
  "dns": [{"timestamp": "2024-01-02T00:00:00Z", "query": "example.org", "query_type": 1}],
  "http": [{"timestamp": "2024-01-02T00:00:00Z", "method": "GET", "host": "portal.example.org", "uri": "/status"}]
}''', encoding='utf-8')
PY
```

## 3. Evidence registrieren

```bash
forensic-cli --workspace ~/cases evidence add \
    --case minimal_case \
    --path ~/cases/minimal_case/input/disk_stub.dd \
    --type disk \
    --description "Synthetic stub file for dry-run"
```

## 4. Module ausführen

```bash
# Filesystem (Dry-Run auf Stub-Datei)
forensic-cli --workspace ~/cases modules run filesystem \
    --case minimal_case \
    --param image=cases/minimal_case/input/disk_stub.dd \
    --dry-run

# Netzwerk-Analyse auf JSON-Fallback (echte Ausführung ohne Binärdaten)
forensic-cli --workspace ~/cases modules run network \
    --case minimal_case \
    --param pcap_json=cases/minimal_case/input/flows.json

# Timeline aus Netzwerkbefunden (Dry-Run ausreichend)
forensic-cli --workspace ~/cases modules run timeline \
    --case minimal_case \
    --param source=cases/minimal_case/analysis/network \
    --param format=csv \
    --dry-run
```

## 5. Report vorbereiten (Dry-Run)

```bash
forensic-cli --workspace ~/cases report generate \
    --case minimal_case \
    --fmt html \
    --out cases/minimal_case/reports/minimal_case.html \
    --dry-run
```

## Artefakte & Logs

- `cases/minimal_case/analysis/network/network.json` – JSON-Ergebnis des Network-Moduls.
- `cases/minimal_case/meta/provenance.jsonl` – dokumentiert Parameterquellen (`cli`, `default`).
- `cases/minimal_case/logs/modules/*` – Dry-Run-Protokolle mit Guard-Hinweisen.

Weitere Beispiele finden Sie im [User Guide](../User-Guide.md) und in den [Tutorials](../tutorials/02_network-timeline-walkthrough.md).
<!-- AUTODOC:END -->

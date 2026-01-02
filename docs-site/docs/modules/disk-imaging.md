<!-- AUTODOC:BEGIN -->
---
title: "Disk Imaging Module"
description: "Creates verified forensic images using dd, ddrescue or ewfacquire with automatic hashing."
---

# Zusammenfassung

- **Kategorie:** Acquisition
- **CLI-Name:** `disk_imaging`
- **Guard-Level:** Hard — requires root, block device access, and explicit confirmation of imaging target.
- **Unterstützte Evidenz:** disk, partition
- **Backends/Extras:** dd, ddrescue, ewfacquire
- **Abhängigkeiten:** dd, ddrescue, ewfacquire (optional)
- **Optionale Extras:** —

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `source` | Yes | — | Pfad zum Block-Device, z. B. /dev/sdb. |
| `output` | Yes | cases/<case>/acq/disk_image_<ts>.img | Zielpfad für Image oder E01-Datei. |
| `tool` | No | ddrescue | Imaging-Backend: dd / ddrescue / ewfacquire. |
| `hash_algorithm` | No | sha256 | Hash für Verifikation (sha256, sha1, md5). |
| `block_size` | No | 4M | Blockgröße für dd-Basiertes Imaging. |
| `skip_verify` | No | false | Verzicht auf Hash-Verifikation (nicht empfohlen). |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run disk_imaging --case demo_case --param source=/dev/sdz --param out=cases/demo_case/acq/disk01.E01 --dry-run
```

**Ausführung**
```bash
sudo forensic-cli modules run disk_imaging --case demo_case --param source=/dev/sdz --param out=cases/demo_case/acq/disk01.E01 --param hash_algorithm=sha256 --enable-live-capture
```

## Ausgaben & Provenienz
- Forensisches Image (RAW oder E01) unter cases/<case>/acq/.
- Hash- und Metadatendatei (JSON) pro Lauf.
- Logfile unter logs/modules/disk_imaging-<timestamp>.log.

**Chain of Custody:** Ketteneinträge in meta/chain_of_custody.jsonl, Parameter in meta/provenance.jsonl.

## Guard-Fehlermeldungen
- `Source device not found` wenn Pfad ungültig.
- `Source is not a block device` bei regulären Dateien.
- Missing tool result wenn dd/ddrescue/ewfacquire fehlen (Status `skipped`).

## Verwandte Dokumentation
- [Acquisition](../MODULES/acquisition.md)
- [Developer Guide](../guides/developer-guide.md)

<!-- AUTODOC:END -->

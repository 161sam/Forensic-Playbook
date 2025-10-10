<!-- AUTODOC:BEGIN -->
---
title: "Memory Analysis Module"
description: "Führt Volatility-Analysen durch (Prozesse, Netzwerk, Malware, Strings)."
---

# Zusammenfassung

- **Kategorie:** Analysis
- **CLI-Name:** `memory_analysis`
- **Guard-Level:** Medium — benötigt Volatility, arbeitet auf bestehenden Dumps.
- **Unterstützte Evidenz:** memory dumps
- **Backends/Extras:** Volatility 3 (bevorzugt), Volatility 2
- **Abhängigkeiten:** volatility3 oder volatility
- **Optionale Extras:** memory extra

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `dump` | Yes | — | Pfad zum Speicherdump (RAW/AVML). |
| `profile` | No | auto | Optionales Profil/OS. |
| `processes` | No | true | Prozesslisten extrahieren. |
| `network` | No | true | Netzwerkverbindungen analysieren. |
| `registry` | No | false | Registry-Artefakte (Windows). |
| `malware` | No | true | Malware-Indikatoren prüfen. |
| `strings` | No | false | Strings aus dem Dump extrahieren. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run memory_analysis --case demo_case --param dump=cases/demo_case/acq/memdump/host.raw --dry-run
```

**Ausführung**
```bash
forensic-cli modules run memory_analysis --case demo_case --param dump=cases/demo_case/acq/memdump/host.raw --param registry=true
```

## Ausgaben & Provenienz
- JSON-/CSV-Berichte zu Prozessen, Netzwerk, Malware-Hinweisen.
- Optional Strings-Datei im Output-Verzeichnis.

**Chain of Custody:** Jedes Plugin liefert Hashes und Pfade; Provenienz referenziert Volatility-Version.

## Guard-Fehlermeldungen
- Missing tool result falls keine Volatility-Version verfügbar.
- `Memory dump not found` bei falschem Pfad.

## Verwandte Dokumentation
- [Analysis](../MODULES/analysis.md)
- [Memory Dump](memory_dump.md)

<!-- AUTODOC:END -->

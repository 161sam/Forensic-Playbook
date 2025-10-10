<!-- AUTODOC:BEGIN -->
---
title: "Reporting Modules"
description: "Artefaktexport und Reportgenerierung."
---

# Übersicht

Reporting-Module konsolidieren Befunde in Markdown, HTML und optional PDF. Sie greifen ausschließlich auf bereits erzeugte Analyseartefakte zu.

## Modulübersicht
| Modul | Guard | Backends | Anforderungen |
| --- | --- | --- | --- |
| Reporting Exporter (`report.generate`) | Medium | Jinja2, JSON writer | jinja2, optional report_pdf |
| Reporting Generator (`report.generate`) | Medium | Template Engine + optional PDF | wkhtmltopdf oder WeasyPrint (optional) |

## Betriebsnotizen
- PDF-Erstellung ist optional und wird bei fehlenden Toolchains als Guard-Warnung markiert.
- Reports werden unter `cases/<case>/reports/` geschrieben und mit Hashes versehen.
- Der Exporter liefert strukturierte JSON/Markdown für SOC-Weitergabe.

## Weiterführende Ressourcen
- [Reporting Html Pdf](../examples/reporting-html-pdf.md)

<!-- AUTODOC:END -->

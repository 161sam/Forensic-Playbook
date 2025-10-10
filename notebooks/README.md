# Forensic Playbook Notebook Suite (Scaffold)

This directory hosts the guarded, deterministic notebook labs that will guide
analysts through the Forensic Playbook workflows. All notebooks default to
**dry-run mode** and never rely on external binary fixtures.

## Run Modes

- **SDK-only:** Execute the Python SDK cells to simulate workflows without any
  external tooling.
- **CLI + SDK (optional):** If `forensic-cli` is available on the PATH, mirror
  the SDK actions with the CLI equivalents. Cells automatically skip CLI steps
  when the binary is absent.
- **MCP Dry-Run (upcoming):** Later labs will surface the Codex/MCP tooling
  catalogue and confirm-gate flows without contacting external services.

## Lab Index

| Lab | Title | Focus |
| --- | ----- | ----- |
| 00 | [Introduction and Guarded Setup](00_Introduction_and_Setup.ipynb) | Guardrails, dry-run defaults, SDK bootstrap |
| 10 | [Case Management and CoC](10_Case_Management_and_CoC.ipynb) | Case lifecycle, chain-of-custody (skeleton) |
| 20 | [Network to Timeline](20_Network_to_Timeline.ipynb) | Network artefacts to timelines (skeleton) |
| 40 | [Router Suite Workflow](40_Router_Suite_Workflow.ipynb) | Router exports & manifests (skeleton) |
| 60 | [Memory and Registry](60_Memory_and_Registry.ipynb) | Memory triage & registry guards (skeleton) |
| 80 | [Malware and IoCs](80_Malware_and_IOCs.ipynb) | IoC scanning guardrails (skeleton) |
| 90 | [Reporting and Codex MCP](90_Reporting_and_Codex_MCP.ipynb) | Reporting flows & MCP gateways (skeleton) |

Exercises and solutions will live under `notebooks/exercises/` and
`notebooks/solutions/` once authored.

## Artefact Locations

Every lab writes deterministic artefacts to the hidden `.labs/` directory at
repository root. The helper `lab_root(<lab_id>)` from `_utils/common.py` ensures
stable paths such as:

```
.labs/00_introduction_and_setup/
.labs/10_case_management/
```

Outputs follow timestamped naming via the `_ts()` helper (UTC). JSON and CSV
writers enforce sorted keys and rows for reproducibility.

## Execution Hints

1. Create and activate a virtual environment: `python -m venv .venv && source
   .venv/bin/activate`.
2. Install the project in editable mode: `pip install -e .`.
3. Launch Jupyter (`jupyter lab` or `jupyter notebook`) from the repository
   root. Run notebooks sequentially; each begins with a **Guarded Setup** block
   that reports CLI availability and artefact paths.
4. Continuous Integration will execute the notebooks in tolerant mode once the
   suite is fully populated.

Guardrail reminders: avoid modifying artefacts manually, capture provenance in
notebook outputs, and keep dry-run defaults intact.

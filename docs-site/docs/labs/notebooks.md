# Forensic Playbook Notebook Suite

The notebooks under this directory provide guarded, deterministic walkthroughs
of the Forensic Playbook workflows. Every lab defaults to **dry-run mode**,
keeps artefacts under `.labs/`, and avoids non-deterministic randomness.

## Run Modes

- **SDK-first:** Execute the Python cells to exercise the framework without
  requiring external binaries.
- **CLI Parity (optional):** When `forensic-cli` is available, mirror key steps
  using the CLI helpers. Cells automatically skip CLI execution otherwise.
- **MCP / Codex Dry-Run:** Dedicated labs surface Codex plans, confirm-gates,
and the MCP catalogue without contacting external services.

## Lab Index

| Lab | Title | Highlights |
| --- | ----- | ---------- |
| 00 | [Introduction and Guarded Setup](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/00_Introduction_and_Setup.ipynb) | Framework bootstrap, configuration precedence, diagnostic dry-runs |
| 10 | [Case Management and CoC](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/10_Case_Management_and_CoC.ipynb) | Create cases, record chain-of-custody entries, inspect evidence tables |
| 20 | [Network to Timeline](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/20_Network_to_Timeline.ipynb) | Synthetic PCAP JSON → network analysis → unified timeline with visualisation |
| 40 | [Router Suite Workflow](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/40_Router_Suite_Workflow.ipynb) | Synthetic router export, env→extract→manifest→summary pipeline, CLI preview |
| 60 | [Memory and Registry](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/60_Memory_and_Registry.ipynb) | Volatility/RegRipper guards, synthetic memory & registry metadata, module path demo |
| 80 | [Malware and IoCs](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/80_Malware_and_IOCs.ipynb) | Deterministic IoC catalogue, defang/refang helper, JSON/CSV match exports |
| 90 | [Reporting and Codex MCP](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/90_Reporting_and_Codex_MCP.ipynb) | HTML report generation, PDF guard, Codex plans, MCP catalogue + confirm-gates |

### Exercises & Solutions

| Lab | Exercise | Solution |
| --- | -------- | -------- |
| 20 | [Exercise](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/exercises/20_Network_to_Timeline_exercise.ipynb) | [Solution](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/solutions/20_Network_to_Timeline_solution.ipynb) |
| 40 | [Exercise](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/exercises/40_Router_Suite_Workflow_exercise.ipynb) | [Solution](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/solutions/40_Router_Suite_Workflow_solution.ipynb) |
| 90 | [Exercise](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/exercises/90_Reporting_and_Codex_MCP_exercise.ipynb) | [Solution](https://github.com/161sam/Forensic-Playbook/blob/main/notebooks/solutions/90_Reporting_and_Codex_MCP_solution.ipynb) |

## Artefact Locations

Each lab writes outputs to `.labs/<lab_id>/…` using the helper
`lab_root(<lab_id>)`. Timestamps come from `_ts()` (UTC) and JSON/CSV writers
sort keys/rows for reproducibility.

## Execution Hints

1. Create a virtual environment (`python -m venv .venv && source .venv/bin/activate`).
2. Install the project in editable mode: `pip install -e .`.
3. Launch Jupyter from the repository root and run the labs sequentially. The
   **Guarded Setup** block at the top of each notebook reports CLI availability
   and artefact locations.
4. CI executes a tolerant nbconvert run of `00_*`, `10_*`, `20_*`, `40_*`, and
   `90_*` notebooks to ensure the suite remains runnable.

Guardrail reminders: avoid manual artefact edits, capture provenance in output
cells, and keep dry-run defaults intact.

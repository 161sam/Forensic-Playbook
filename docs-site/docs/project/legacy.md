# Legacy Scripts

The following scripts are retained for compatibility with pre-2.x workflows. New
implementations live inside the Python framework and are exposed through
`forensic-cli`. Legacy tooling is disabled by default and can be re-enabled via
`forensic-cli --legacy ...`. See the **Invocation** column for details.

| Name | Purpose | Replacement | Status | Invocation |
| --- | --- | --- | --- | --- |
| `scripts/ioc_grep.sh` | Grep-based indicator sweep across filesystem paths | `forensic modules run ioc_scan` (if available) | Deprecated | `forensic-cli --legacy legacy ioc-grep [args]` |
| `scripts/quick-triage.sh` | Legacy shell wrapper around triage checklist | `forensic modules run quick_triage` | Deprecated | `forensic-cli --legacy legacy quick-triage` |
| `scripts/harden_ssh.sh` | SSH hardening helper (non-forensic) | Not part of the framework | Out of scope | Execute manually if required |

## Router Scripts

The router toolkit retains the original Bash automation for environments that
cannot install the Python framework. Every helper now has a guarded Python
equivalent exposed through `forensic-cli router ...`. Opt-in execution of the
legacy variants is available via the `--legacy` flag on each sub-command.

| Legacy script | Python replacement | CLI usage | Notes |
| --- | --- | --- | --- |
| `router/scripts/prepare_env.sh` | `forensic.modules.router.env.init_environment` | `forensic-cli router env init [--legacy]` | Workspace bootstrap |
| `router/scripts/tcpdump_setup.sh` | `forensic.modules.router.capture.setup` | `forensic-cli router capture setup [--legacy]` | Directory preparation |
| `router/scripts/tcpdump_passive_capture.sh` | `forensic.modules.router.capture.start` | `forensic-cli router capture start [--legacy]` | Guarded tcpdump launch |
| `router/scripts/tcpdump_passive_stop.sh` | `forensic.modules.router.capture.stop` | `forensic-cli router capture stop [--legacy]` | Friendly stop guidance |
| `router/scripts/extract_ui_artifacts.sh` | `forensic.modules.router.extract.extract(kind="ui")` | `forensic-cli router extract ui [--legacy]` | Router UI artefacts |
| `router/scripts/analyze_ui_artifacts.sh` | Covered by `router extract ui` | `forensic-cli router extract ui` | Analysis handled inline |
| `router/scripts/collect_router_ui.py` | Covered by `router extract ui` | `forensic-cli router extract ui` | Python-first implementation |
| `router/scripts/extract_ddns.sh` | `forensic.modules.router.extract.extract(kind="ddns")` | `forensic-cli router extract ddns [--legacy]` | DDNS configuration |
| `router/scripts/extract_devices.sh` | `forensic.modules.router.extract.extract(kind="devices")` | `forensic-cli router extract devices [--legacy]` | Connected devices |
| `router/scripts/extract_eventlog.sh` | `forensic.modules.router.extract.extract(kind="eventlog")` | `forensic-cli router extract eventlog [--legacy]` | Event log parsing |
| `router/scripts/extract_portforwards.sh` | `forensic.modules.router.extract.extract(kind="portforwards")` | `forensic-cli router extract portforwards [--legacy]` | Port forward rules |
| `router/scripts/extract_session_csrf.sh` | `forensic.modules.router.extract.extract(kind="session_csrf")` | `forensic-cli router extract session_csrf [--legacy]` | Session/CSRF data |
| `router/scripts/extract_tr069.sh` | `forensic.modules.router.extract.extract(kind="tr069")` | `forensic-cli router extract tr069 [--legacy]` | TR-069 provisioning |
| `router/scripts/find_backups.sh` | `forensic.modules.router.extract.extract(kind="backups")` | `forensic-cli router extract backups [--legacy]` | Backup discovery |
| `router/scripts/generate_evidence_manifest.sh` | `forensic.modules.router.manifest.write_manifest` | `forensic-cli router manifest write [--legacy]` | Manifest + hashes |
| `router/scripts/run_forensic_pipeline.sh` | `forensic.modules.router.pipeline.run_pipeline` | `forensic-cli router pipeline run [--legacy]` | Orchestrated workflow |
| `router/scripts/summarize_report.sh` | `forensic.modules.router.summarize.summarize` | `forensic-cli router summarize [--legacy]` | Report summarisation |

## Migration Notes

* Prefer native modules via `forensic-cli modules run ...` wherever possible.
* Legacy scripts are not shipped with the Python package when installed from
  PyPI. If you rely on a shell wrapper, pin to a git checkout or migrate to the
  module-based workflow.
* For optional modules that depend on external tooling (e.g. `yara`, `tcpdump`),
  the CLI will highlight skipped modules with guard messages.

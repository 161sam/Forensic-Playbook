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

## Migration Notes

* Prefer native modules via `forensic-cli modules run ...` wherever possible.
* Legacy scripts are not shipped with the Python package when installed from
  PyPI. If you rely on a shell wrapper, pin to a git checkout or migrate to the
  module-based workflow.
* For optional modules that depend on external tooling (e.g. `yara`, `tcpdump`),
  the CLI will highlight skipped modules with guard messages.

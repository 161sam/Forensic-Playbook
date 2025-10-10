#!/usr/bin/env python3
# Repo-Hilfen, nicht mit forensic.tools verwechseln
"""Generate the module capability matrix for the README."""

from __future__ import annotations

import ast
import importlib
import importlib.util
import shutil
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = REPO_ROOT / "forensic" / "modules"
README_PATH = REPO_ROOT / "README.md"
MARKER_BEGIN = "<!-- MODULE_MATRIX:BEGIN -->"
MARKER_END = "<!-- MODULE_MATRIX:END -->"

def _ensure_requests_stub() -> None:
    """Provide a lightweight ``requests`` stub when the dependency is missing.

    The module matrix generator imports the ``forensic`` package to introspect
    module metadata. Importing ``forensic`` pulls in the MCP client which, in
    turn, depends on the third-party ``requests`` package. CI environments that
    only install minimal tooling do not necessarily ship with ``requests``
    pre-installed which previously caused the import step to fail and the
    generated table to contain noisy "Import error" entries.

    To keep the generator deterministic and avoid adding an implicit runtime
    dependency, we stub the parts of ``requests`` that are touched during import
    (``Session`` construction and the base ``RequestException`` hierarchy). The
    stub raises if the generator accidentally exercises runtime behaviour so we
    get a clear signal rather than silently masking new usages.
    """

    if importlib.util.find_spec("requests") is not None:
        return

    stub = types.ModuleType("requests")

    class _StubSession:  # pragma: no cover - defensive stub
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401 - simple stub
            raise RuntimeError(
                "requests.Session stub invoked during module matrix generation"
            )

    class _StubRequestException(Exception):
        """Placeholder for :class:`requests.RequestException`."""

    stub.Session = _StubSession
    stub.RequestException = _StubRequestException
    stub.exceptions = types.SimpleNamespace(RequestException=_StubRequestException)

    sys.modules.setdefault("requests", stub)


_ensure_requests_stub()

sys.path.insert(0, str(REPO_ROOT))


CATEGORY_LABELS = {
    "acquisition": "Acquisition",
    "analysis": "Analysis",
    "triage": "Triage",
    "reporting": "Reporting",
}

MVP_DEFAULT_NOTES = "MVP baseline implementation"

STATIC_TOOL_HINTS = {
    "forensic.modules.acquisition.disk_imaging": ["ddrescue", "ewfacquire"],
}

BACKEND_HINTS = {
    "forensic.modules.acquisition.disk_imaging": "ddrescue / ewfacquire",
    "forensic.modules.acquisition.live_response": "coreutils (uname, ps, netstat)",
    "forensic.modules.acquisition.memory_dump": "avml",
    "forensic.modules.acquisition.network_capture": "tcpdump / dumpcap",
    "forensic.modules.analysis.filesystem": "sleuthkit (fls, blkcat)",
    "forensic.modules.analysis.malware": "yara extra",
    "forensic.modules.analysis.memory": "memory extra (volatility3)",
    "forensic.modules.analysis.network": "pcap extra (scapy, pyshark)",
    "forensic.modules.analysis.registry": "reglookup / rip.pl",
    "forensic.modules.analysis.timeline": "log2timeline.py / mactime",
    "forensic.modules.reporting.exporter": "report_pdf extra (weasyprint)",
    "forensic.modules.reporting.generator": "jinja2 templates",
    "forensic.modules.triage.persistence": "filesystem inspection",
    "forensic.modules.triage.quick_triage": "POSIX utilities",
    "forensic.modules.triage.system_info": "platform / socket APIs",
    "forensic.modules.router.capture": "router-suite",
    "forensic.modules.router.common": "router-suite",
    "forensic.modules.router.env": "router-suite",
    "forensic.modules.router.extract": "router-suite",
    "forensic.modules.router.manifest": "router-suite",
    "forensic.modules.router.pipeline": "router-suite",
    "forensic.modules.router.summarize": "router-suite",
}

STATUS_OVERRIDES = {
    "forensic.modules.acquisition.live_response": "Guarded",
    "forensic.modules.acquisition.network_capture": "Guarded",
    "forensic.modules.analysis.network": "Guarded",
    "forensic.modules.reporting.generator": "Guarded",
    "forensic.modules.triage.persistence": "Guarded",
    "forensic.modules.triage.quick_triage": "Guarded",
    "forensic.modules.triage.system_info": "Guarded",
    "forensic.modules.router.capture": "Guarded",
    "forensic.modules.router.common": "Guarded",
    "forensic.modules.router.env": "Guarded",
    "forensic.modules.router.extract": "Guarded",
    "forensic.modules.router.manifest": "Guarded",
    "forensic.modules.router.pipeline": "Guarded",
    "forensic.modules.router.summarize": "Guarded",
}

GUARD_HINTS = {
    "forensic.modules.acquisition.disk_imaging": "Root + block device access",
    "forensic.modules.acquisition.memory_dump": "--enable-live-capture (Linux)",
    "forensic.modules.acquisition.network_capture": "--enable-live-capture + root",
    "forensic.modules.router.capture": "Dry-run default; tools optional",
    "forensic.modules.router.common": "Dry-run default; tools optional",
    "forensic.modules.router.env": "Dry-run default; tools optional",
    "forensic.modules.router.extract": "Dry-run default; tools optional",
    "forensic.modules.router.manifest": "Dry-run default; tools optional",
    "forensic.modules.router.pipeline": "Dry-run default; tools optional",
    "forensic.modules.router.summarize": "Dry-run default; tools optional",
}

# Certain guarded modules provide fallbacks where any tool in the group is
# sufficient to run the module. These groups should be considered satisfied if
# *any* of the tools are available locally. This avoids incorrectly flagging a
# module as partially unavailable when an alternative implementation exists.
ALTERNATIVE_TOOL_GROUPS = {
    "forensic.modules.acquisition.live_response": [
        {"netstat", "ss"},
    ],
}


def _format_tool_choices(import_path: str, tools: Sequence[str]) -> str:
    """Return a human friendly representation of required tooling."""

    groups = ALTERNATIVE_TOOL_GROUPS.get(import_path, [])
    tools_set = set(tools)
    consumed: set[str] = set()
    parts: list[str] = []

    for group in groups:
        if group.issubset(tools_set):
            choices = sorted(group)
            if not choices:
                continue
            if len(choices) == 1:
                parts.append(choices[0])
            elif len(choices) == 2:
                parts.append(" or ".join(choices))
            else:
                head = ", ".join(choices[:-1])
                parts.append(f"{head}, or {choices[-1]}")
            consumed.update(group)

    for tool in tools:
        if tool not in consumed:
            parts.append(tool)

    return ", ".join(parts)


@dataclass
class ModuleRow:
    category: str
    module: str
    status: str
    notes: str
    backend: str
    guard: str


def iter_module_files() -> Iterable[Tuple[str, Path]]:
    for category_dir in sorted(MODULE_ROOT.iterdir()):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        for module_path in sorted(category_dir.glob("*.py")):
            if module_path.name == "__init__.py":
                continue
            yield category, module_path


def extract_static_tools(module_path: Path) -> List[str]:
    tools: List[str] = []
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(module_path))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "TOOLS",
                    "REQUIRED_TOOLS",
                }:
                    value = ast.literal_eval(node.value)
                    if isinstance(value, list | tuple):
                        tools.extend(str(item) for item in value)
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "_verify_tool"
                and node.args
            ):
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    tools.append(arg.value)
            if isinstance(func, ast.Attribute) and func.attr == "which" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    tools.append(arg.value)
    return sorted(set(tools))


def _classify_tool_availability(
    import_path: str, tools: Sequence[str]
) -> tuple[list[str], list[str]]:
    available = {tool for tool in tools if shutil.which(tool)}
    missing = {tool for tool in tools if tool not in available}

    for group in ALTERNATIVE_TOOL_GROUPS.get(import_path, []):
        if group & available:
            available.update(group)
            missing.difference_update(group)

    return sorted(available), sorted(missing)


def format_notes(
    import_path: str,
    status: str,
    tools: Sequence[str],
    import_error: Exception | None,
) -> str:
    if import_error is not None:
        return f"Import error: {import_error}"

    if status == "Guarded" and tools:
        tool_display = _format_tool_choices(import_path, tools)
        available, missing = _classify_tool_availability(import_path, tools)
        if missing and available:
            return f"Requires {tool_display} (missing: {', '.join(missing)})"
        if missing:
            return f"Requires {tool_display} (missing locally)"
        return f"Requires {tool_display} (all available)"

    if status == "MVP":
        return MVP_DEFAULT_NOTES

    return ""


def build_rows() -> List[ModuleRow]:
    rows: List[ModuleRow] = []
    for category, module_path in iter_module_files():
        module_name = module_path.stem
        import_path = f"forensic.modules.{category}.{module_name}"
        import_error: Exception | None = None
        tools = extract_static_tools(module_path)
        hint_tools = STATIC_TOOL_HINTS.get(import_path, [])
        if hint_tools:
            tools = sorted(set(list(tools) + list(hint_tools)))

        try:
            importlib.import_module(import_path)
        except Exception as exc:  # pragma: no cover - environment dependent
            import_error = exc

        status_override = STATUS_OVERRIDES.get(import_path)

        if status_override:
            status = status_override
        elif import_error is not None:
            status = "Missing"
        elif tools:
            status = "Guarded"
        else:
            status = "MVP"

        notes = format_notes(import_path, status, tools, import_error)
        label = CATEGORY_LABELS.get(category, category.title())
        backend = BACKEND_HINTS.get(import_path, "")
        guard = GUARD_HINTS.get(import_path, "")
        rows.append(ModuleRow(label, module_name, status, notes, backend, guard))

    return rows


def render_table(rows: Sequence[ModuleRow]) -> str:
    lines = [
        "| Kategorie | Modul | Status | Backend/Extra | Guard | Notizen |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        notes = row.notes if row.notes else "—"
        backend = row.backend if row.backend else "—"
        guard = row.guard if row.guard else "—"
        lines.append(
            f"| {row.category} | `{row.module}` | {row.status} | {backend} | {guard} | {notes} |"
        )
    return "\n".join(lines)


def update_readme(table: str) -> None:
    text = README_PATH.read_text(encoding="utf-8")
    if MARKER_BEGIN not in text or MARKER_END not in text:
        raise SystemExit("README markers for module matrix not found")

    pre, _, rest = text.partition(MARKER_BEGIN)
    middle, _, post = rest.partition(MARKER_END)

    new_middle = f"{MARKER_BEGIN}\n{table}\n{MARKER_END}"
    updated = pre + new_middle + post
    README_PATH.write_text(updated, encoding="utf-8")


def main() -> None:
    rows = build_rows()
    table = render_table(rows)
    update_readme(table)
    print("Module matrix updated.")


if __name__ == "__main__":
    main()

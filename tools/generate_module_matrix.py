#!/usr/bin/env python3
"""Generate the module capability matrix for the README."""

from __future__ import annotations

import ast
import importlib
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = REPO_ROOT / "forensic" / "modules"
README_PATH = REPO_ROOT / "README.md"
MARKER_BEGIN = "<!-- MODULE_MATRIX:BEGIN -->"
MARKER_END = "<!-- MODULE_MATRIX:END -->"

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


@dataclass
class ModuleRow:
    category: str
    module: str
    status: str
    notes: str


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
                if isinstance(target, ast.Name) and target.id in {"TOOLS", "REQUIRED_TOOLS"}:
                    value = ast.literal_eval(node.value)
                    if isinstance(value, list | tuple):
                        tools.extend(str(item) for item in value)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "_verify_tool" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    tools.append(arg.value)
            if isinstance(func, ast.Attribute) and func.attr == "which" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    tools.append(arg.value)
    return sorted(set(tools))


def format_notes(status: str, tools: Sequence[str], import_error: Exception | None) -> str:
    if import_error is not None:
        return f"Import error: {import_error}"

    if status == "Guarded" and tools:
        available = [tool for tool in tools if shutil.which(tool)]
        missing = [tool for tool in tools if tool not in available]
        if missing and available:
            return f"Requires {', '.join(tools)} (missing: {', '.join(missing)})"
        if missing:
            return f"Requires {', '.join(tools)} (missing locally)"
        return f"Requires {', '.join(tools)} (all available)"

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

        if import_error is not None:
            status = "Missing"
        elif tools:
            status = "Guarded"
        else:
            status = "MVP"

        notes = format_notes(status, tools, import_error)
        label = CATEGORY_LABELS.get(category, category.title())
        rows.append(ModuleRow(label, module_name, status, notes))

    return rows


def render_table(rows: Sequence[ModuleRow]) -> str:
    lines = ["| Kategorie | Modul | Status | Notizen |", "| --- | --- | --- | --- |"]
    for row in rows:
        notes = row.notes if row.notes else "—"
        lines.append(
            f"| {row.category} | `{row.module}` | {row.status} | {notes} |"
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

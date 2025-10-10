#!/usr/bin/env python3
# Repo-Hilfen, nicht mit `forensic.tools` verwechseln.
"""Validate the repository layout against the v2.0 baseline."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

CORE_FILES = [
    "forensic/core/framework.py",
    "forensic/core/module.py",
    "forensic/core/evidence.py",
    "forensic/core/chain_of_custody.py",
    "forensic/core/config.py",
    "forensic/core/logger.py",
]

WRAPPER_FILES = [
    "forensic/tools/sleuthkit.py",
    "forensic/tools/volatility.py",
    "forensic/tools/autopsy.py",
    "forensic/tools/plaso.py",
    "forensic/tools/bulk_extractor.py",
    "forensic/tools/yara.py",
]

PACKAGE_DIRS = [
    "forensic",
    "forensic/core",
    "forensic/modules",
    "forensic/modules/acquisition",
    "forensic/modules/analysis",
    "forensic/modules/triage",
    "forensic/modules/reporting",
    "forensic/tools",
    "forensic/utils",
]

ROOT_FILES = ["README.md", "REPORT.md", "Projektstruktur-v2.0.md"]
CONFIG_FILES = ["config/framework.yaml"]


def _find_missing_paths(root: Path, candidates: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for candidate in candidates:
        path = root / candidate
        if not path.exists():
            missing.append(candidate)
    return missing


def _verify_package_inits(root: Path) -> list[str]:
    missing: list[str] = []
    for package in PACKAGE_DIRS:
        init_path = root / package / "__init__.py"
        if not init_path.exists():
            missing.append(str(init_path.relative_to(root)))
    return missing


def _pipelines_present(root: Path) -> bool:
    pipeline_dir = root / "pipelines"
    return pipeline_dir.exists() and any(pipeline_dir.glob("*.yaml"))


def main() -> int:
    root = Path(__file__).resolve().parents[1]

    missing_core = _find_missing_paths(root, CORE_FILES)
    missing_wrappers = _find_missing_paths(root, WRAPPER_FILES)
    missing_roots = _find_missing_paths(root, ROOT_FILES)
    missing_configs = _find_missing_paths(root, CONFIG_FILES)
    missing_packages = _verify_package_inits(root)

    pipelines_ok = _pipelines_present(root)

    if not (
        missing_core
        or missing_wrappers
        or missing_roots
        or missing_configs
        or missing_packages
        or not pipelines_ok
    ):
        print("Project layout validation passed.")
        return 0

    print("Project layout validation failed:")
    if missing_core:
        print("  Missing core files:")
        for path in missing_core:
            print(f"    - {path}")
    if missing_wrappers:
        print("  Missing tool wrappers:")
        for path in missing_wrappers:
            print(f"    - {path}")
    if missing_roots:
        print("  Missing documentation files:")
        for path in missing_roots:
            print(f"    - {path}")
    if missing_configs:
        print("  Missing configuration files:")
        for path in missing_configs:
            print(f"    - {path}")
    if missing_packages:
        print("  Missing package initialisers:")
        for path in missing_packages:
            print(f"    - {path}")
    if not pipelines_ok:
        print("  Missing pipeline definitions (*.yaml under pipelines/).")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

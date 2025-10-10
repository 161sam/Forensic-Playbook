#!/usr/bin/env python3
# Repo-Hilfen, nicht mit forensic.tools verwechseln
"""Validate the Forensic-Playbook repository layout against v2.0 expectations."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[1]

MANDATORY_FILES = [
    "README.md",
    "REPORT.md",
    "Projektstruktur-v2.0.md",
    "config/framework.yaml",
]

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

MODULE_DIRECTORIES = [
    "forensic/modules/acquisition",
    "forensic/modules/analysis",
    "forensic/modules/triage",
    "forensic/modules/reporting",
]

PACKAGE_DIRECTORIES = [
    "forensic",
    "forensic/core",
    "forensic/modules",
    "forensic/modules/acquisition",
    "forensic/modules/analysis",
    "forensic/modules/triage",
    "forensic/modules/reporting",
    "forensic/tools",
]


def _missing_paths(paths: Iterable[str]) -> List[str]:
    missing: List[str] = []
    for rel_path in paths:
        path = REPO_ROOT / rel_path
        if not path.exists():
            missing.append(rel_path)
    return missing


def _missing_package_inits(packages: Iterable[str]) -> List[str]:
    missing: List[str] = []
    for package in packages:
        init_path = REPO_ROOT / package / "__init__.py"
        if not init_path.exists():
            missing.append(f"{package}/__init__.py")
    return missing


def _check_pipelines() -> List[str]:
    pipeline_dir = REPO_ROOT / "pipelines"
    if not pipeline_dir.exists():
        return ["pipelines/"]
    yaml_files = list(pipeline_dir.glob("*.yaml"))
    if not yaml_files:
        return ["pipelines/*.yaml"]
    return []


def _report_missing(title: str, items: List[str]) -> None:
    print(f"- {title}")
    for item in items:
        print(f"  • {item}")


def main() -> int:
    sections: List[tuple[str, List[str]]] = [
        ("Mandatory files", _missing_paths(MANDATORY_FILES)),
        ("Core components", _missing_paths(CORE_FILES)),
        ("Tool wrappers", _missing_paths(WRAPPER_FILES)),
        ("Module directories", _missing_paths(MODULE_DIRECTORIES)),
        ("Python package markers", _missing_package_inits(PACKAGE_DIRECTORIES)),
        ("Pipeline definitions", _check_pipelines()),
    ]

    has_missing = False
    print("Validating Forensic-Playbook project layout (v2.0)...")
    for title, items in sections:
        if items:
            has_missing = True
            _report_missing(title, items)

    if has_missing:
        print("\nLayout validation failed. See missing items above.")
        return 1

    print("All required layout elements are present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

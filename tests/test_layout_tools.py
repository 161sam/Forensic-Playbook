"""Ensure runtime wrappers live exclusively under forensic/tools."""

from __future__ import annotations

from pathlib import Path


def test_runtime_wrappers_not_in_repo_tools() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime_dir = repo_root / "forensic" / "tools"
    repo_tools_dir = repo_root / "tools"

    runtime_stems = {
        path.stem for path in runtime_dir.glob("*.py") if path.name != "__init__.py"
    }
    repo_tool_stems = {
        path.stem for path in repo_tools_dir.glob("*.py") if path.name != "__init__.py"
    }

    assert runtime_stems.isdisjoint(repo_tool_stems)

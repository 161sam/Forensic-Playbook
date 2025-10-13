"""Regression tests for the MCP registry catalogue."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import pytest

from forensic.core.framework import ForensicFramework
from forensic.mcp.registry import build_catalog


@pytest.fixture(name="framework")
def _framework(tmp_path: Path) -> ForensicFramework:
    """Provide an isolated framework instance for registry tests."""

    return ForensicFramework(workspace=tmp_path / "mcp-registry-workspace")


def test_registry_contains_expected_tools(framework: ForensicFramework) -> None:
    """The catalogue must expose core diagnostics, module and router tools."""

    catalog = build_catalog(framework)
    tool_names = set(catalog["metadata"]["tool_names"])

    expected = {
        "diagnostics.ping",
        "cases.list",
        "modules.run",
        "reports.generate",
        "router.capture.start",
    }
    assert expected.issubset(tool_names)

    prompt_info = catalog["prompt"]
    assert prompt_info["resource"] == "forensic/mcp/prompts/forensic_mode.txt"
    assert prompt_info["path"].endswith("forensic_mode.txt")


def test_router_capture_start_schema_sorted(framework: ForensicFramework) -> None:
    """Router capture start metadata must include guard arguments and be sorted."""

    catalog = build_catalog(framework)
    router_entries: Dict[str, dict] = {
        entry["name"]: entry for entry in catalog["tools"]["router"]
    }
    start_entry = router_entries["router.capture.start"]

    argument_names = [argument["name"] for argument in start_entry["arguments"]]
    assert argument_names == sorted(argument_names)
    assert {"enable_live_capture", "dry_run"}.issubset(argument_names)

    guard_argument = next(
        argument
        for argument in start_entry["arguments"]
        if argument["name"] == "enable_live_capture"
    )
    assert "must be true" in guard_argument["description"].lower()

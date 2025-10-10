"""Ensure CLI documentation links reference files that exist."""

from __future__ import annotations

from pathlib import Path

import pytest

DOC_LINKS = {
    Path("README.md"): {
        Path("docs/mcp/codex-workflow.md"),
        Path("docs/mcp/forensic-mode.md"),
        Path("docs/Getting-Started.md"),
    },
    Path("docs/Getting-Started.md"): {
        Path("docs/mcp/codex-workflow.md"),
        Path("docs/mcp/forensic-mode.md"),
    },
}


@pytest.mark.parametrize("source, targets", DOC_LINKS.items())
def test_doc_links_exist(source: Path, targets: set[Path]) -> None:
    """Verify that referenced documentation files are present locally."""

    content = source.read_text(encoding="utf-8")
    for target in sorted(targets):
        assert target.as_posix() in content, f"Expected {target} to be referenced in {source}"
        assert target.exists(), f"Linked documentation {target} is missing"

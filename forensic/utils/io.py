"""I/O helper utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def read_text(path: Path, encoding: str = "utf-8") -> str:
    """Read UTF-8 text from ``path`` safely."""

    if not path.exists():
        return ""
    return path.read_text(encoding=encoding)


def write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write ``content`` to ``path`` creating parent directories."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    """Persist ``data`` as pretty printed JSON."""

    write_text(path, json.dumps(data, indent=2, default=str))


__all__ = ["read_text", "write_json", "write_text"]

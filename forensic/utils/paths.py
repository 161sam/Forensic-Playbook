"""Path related helper utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional


def ensure_directory(path: Path) -> Path:
    """Ensure ``path`` exists and return it."""

    path.mkdir(parents=True, exist_ok=True)
    return path


def resolve_workspace(base: Path, name: str) -> Path:
    """Return the workspace directory derived from ``base`` and ``name``."""

    return ensure_directory(base / name)


def resolve_config_paths(root: Path, filenames: Iterable[str]) -> Iterable[Path]:
    """Yield configuration file paths that exist."""

    for filename in filenames:
        candidate = root / filename
        if candidate.exists():
            yield candidate


def optional_path(value: Optional[str]) -> Optional[Path]:
    """Convert optional string to :class:`Path` if present."""

    if value:
        return Path(value).expanduser()
    return None


__all__ = [
    "ensure_directory",
    "optional_path",
    "resolve_config_paths",
    "resolve_workspace",
]

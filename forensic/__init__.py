"""Forensic Playbook package initialization."""

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:  # pragma: no cover - depends on package metadata
    __version__ = version("forensic-playbook")
except PackageNotFoundError:  # pragma: no cover - local development fallback
    __version__ = "0.2.0-dev"

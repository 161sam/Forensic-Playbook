#!/usr/bin/env python3
"""Backward compatible entry point for the Forensic Playbook CLI."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forensic.cli import cli as _cli
from forensic.cli import main as _framework_main

DEPRECATION_NOTICE = (
    "Warning: 'scripts/forensic-cli.py' is deprecated; use 'forensic-cli' instead."
)


def main() -> None:
    """Emit a deprecation warning before delegating to :mod:`forensic.cli`."""

    print(DEPRECATION_NOTICE, file=sys.stderr)
    print("Delegating to 'forensic-cli'...", file=sys.stderr)
    _framework_main()


cli = _cli

__all__ = ["cli", "main"]


if __name__ == "__main__":  # pragma: no cover - legacy shim
    main()

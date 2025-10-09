#!/usr/bin/env python3
"""Backward compatible entry point for the Forensic Playbook CLI."""

from forensic.cli import cli, main

__all__ = ["cli", "main"]

if __name__ == "__main__":  # pragma: no cover - legacy shim
    main()

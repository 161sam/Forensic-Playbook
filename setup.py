#!/usr/bin/env python3
"""Compatibility shim for setuptools-based builds."""

from setuptools import setup

if __name__ == "__main__":  # pragma: no cover - packaging utility
    setup()

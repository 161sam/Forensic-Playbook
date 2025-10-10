"""Guarded wrappers around external forensic tooling.

The modules exported here provide light-weight detection and read-only
interfaces for commonly used third-party tools. They are intentionally
minimal and avoid executing heavy actions so they can be safely imported in
any environment.
"""

from . import autopsy, bulk_extractor, plaso, sleuthkit, volatility, yara

__all__ = [
    "autopsy",
    "bulk_extractor",
    "plaso",
    "sleuthkit",
    "volatility",
    "yara",
]

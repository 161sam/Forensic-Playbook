"""UTC time helper utilities for the forensic playbook."""

from __future__ import annotations

from datetime import datetime, timezone

ISO_Z_SUFFIX = "Z"


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_slug() -> str:
    """Return a filesystem-friendly UTC timestamp (YYYYMMDD_HHMMSS)."""
    return utc_now().strftime("%Y%m%d_%H%M%S")


def utc_isoformat() -> str:
    """Return an ISO-8601 timestamp with an explicit trailing Z suffix."""
    return utc_now().isoformat().replace("+00:00", ISO_Z_SUFFIX)


def utc_display() -> str:
    """Return a human-friendly UTC timestamp for reports/logs."""
    return utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")

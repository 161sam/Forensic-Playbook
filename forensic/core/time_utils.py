"""UTC and timezone helper utilities for the forensic playbook."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

try:  # Python 3.9+ provides :mod:`zoneinfo` in the standard library.
    from zoneinfo import ZoneInfo  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency at runtime
    ZoneInfo = None  # type: ignore[assignment]

ISO_Z_SUFFIX = "Z"


def _coerce_timezone(name: Optional[str]) -> timezone:
    """Return a timezone object for ``name`` falling back to UTC."""

    if not name:
        return timezone.utc

    if ZoneInfo is None:  # pragma: no cover - environment dependent
        return timezone.utc

    try:
        return ZoneInfo(name)  # type: ignore[return-value]
    except Exception:  # pragma: no cover - invalid tz database name
        return timezone.utc


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def timezone_now(timezone_name: Optional[str] = None) -> datetime:
    """Return the current datetime in ``timezone_name`` (defaults to UTC)."""

    tzinfo = _coerce_timezone(timezone_name)
    return datetime.now(tz=tzinfo)


def utc_slug() -> str:
    """Return a filesystem-friendly UTC timestamp (YYYYMMDD_HHMMSS)."""
    return utc_now().strftime("%Y%m%d_%H%M%S")


def utc_isoformat() -> str:
    """Return an ISO-8601 timestamp with an explicit trailing Z suffix."""
    return utc_now().isoformat().replace("+00:00", ISO_Z_SUFFIX)


def isoformat_with_timezone(timezone_name: Optional[str] = None) -> str:
    """Return an ISO-8601 timestamp normalised to ``timezone_name``."""

    tzinfo = _coerce_timezone(timezone_name)
    now = timezone_now(timezone_name)
    if tzinfo == timezone.utc:
        return now.isoformat().replace("+00:00", ISO_Z_SUFFIX)
    return now.isoformat()


def utc_display() -> str:
    """Return a human-friendly UTC timestamp for reports/logs."""
    return utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")

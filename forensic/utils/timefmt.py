"""Time formatting utilities."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""

    return datetime.now(timezone.utc).strftime(ISO_FORMAT)


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    """Convert a datetime to ISO 8601 (UTC) string."""

    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(ISO_FORMAT)


__all__ = ["ISO_FORMAT", "to_iso", "utcnow_iso"]

"""Time formatting utilities with configurable timezone support."""

from __future__ import annotations

import functools
from datetime import datetime, timezone
from typing import Optional

try:  # pragma: no cover - standard library dependency may be unavailable
    from zoneinfo import ZoneInfo  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - ZoneInfo unavailable on platform
    ZoneInfo = None  # type: ignore[assignment]

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_OVERRIDE_TIMEZONE: Optional[str] = None


@functools.lru_cache(maxsize=1)
def _config_timezone() -> str:
    """Resolve the framework timezone from configuration (fallback UTC)."""

    try:
        from forensic.core.config import get_config  # Local import to avoid cycles

        config = get_config()
    except Exception:  # pragma: no cover - defensive fallback when config fails
        return "UTC"

    return getattr(config, "timezone", "UTC") or "UTC"


def _timezone_name(timezone_name: Optional[str] = None) -> str:
    """Return the active timezone name honouring overrides and config."""

    if timezone_name:
        return timezone_name
    if _OVERRIDE_TIMEZONE is not None:
        return _OVERRIDE_TIMEZONE
    return _config_timezone()


def _coerce_timezone(name: Optional[str]) -> timezone:
    """Resolve a :class:`datetime.timezone` (or equivalent) for ``name``."""

    if not name or str(name).upper() in {"UTC", "Z"}:
        return timezone.utc

    if ZoneInfo is None:  # pragma: no cover - environment dependent fallback
        return timezone.utc

    try:
        return ZoneInfo(str(name))  # type: ignore[return-value]
    except Exception:  # pragma: no cover - invalid timezone specification
        return timezone.utc


def set_default_timezone(timezone_name: Optional[str]) -> None:
    """Override the default timezone used by :func:`to_iso`.

    Passing ``None`` resets the override causing the configured timezone to be
    used again on subsequent calls.
    """

    global _OVERRIDE_TIMEZONE
    _OVERRIDE_TIMEZONE = timezone_name if timezone_name else None


def _format(dt: datetime, tzinfo: timezone) -> str:
    """Format ``dt`` in ``tzinfo`` using ISO-8601 semantics."""

    converted = dt.astimezone(tzinfo)
    if tzinfo == timezone.utc:
        return converted.isoformat().replace("+00:00", "Z")
    return converted.isoformat()


def utcnow_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""

    return datetime.now(timezone.utc).strftime(ISO_FORMAT)


def to_iso(dt: Optional[datetime], timezone_name: Optional[str] = None) -> Optional[str]:
    """Convert ``dt`` to an ISO 8601 string honouring configured timezone."""

    if dt is None:
        return None

    tzinfo = _coerce_timezone(_timezone_name(timezone_name))

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tzinfo)

    return _format(dt, tzinfo)


__all__ = ["ISO_FORMAT", "set_default_timezone", "to_iso", "utcnow_iso"]

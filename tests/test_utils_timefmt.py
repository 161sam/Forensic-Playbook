from __future__ import annotations

from datetime import datetime, timezone

import pytest

from forensic.utils import timefmt

try:  # pragma: no cover - zoneinfo optional on some platforms
    import zoneinfo  # type: ignore  # noqa: F401

    ZONEINFO_AVAILABLE = True
except Exception:  # pragma: no cover - zoneinfo unavailable
    ZONEINFO_AVAILABLE = False


def test_to_iso_handles_none() -> None:
    assert timefmt.to_iso(None) is None


def test_to_iso_preserves_timezone() -> None:
    aware = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert timefmt.to_iso(aware) == "2024-01-01T12:00:00Z"


def test_to_iso_defaults_to_utc_for_naive_datetime() -> None:
    naive = datetime(2024, 1, 1, 12, 0, 0)
    assert timefmt.to_iso(naive) == "2024-01-01T12:00:00Z"


@pytest.mark.skipif(not ZONEINFO_AVAILABLE, reason="zoneinfo not available")
def test_to_iso_respects_override_timezone() -> None:
    naive = datetime(2024, 1, 1, 12, 0, 0)
    aware = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    timefmt.set_default_timezone("Europe/Berlin")
    try:
        assert timefmt.to_iso(naive) == "2024-01-01T12:00:00+01:00"
        assert timefmt.to_iso(aware) == "2024-01-01T11:00:00+01:00"
        assert timefmt.to_iso(aware, timezone_name="UTC") == "2024-01-01T10:00:00Z"
    finally:
        timefmt.set_default_timezone(None)

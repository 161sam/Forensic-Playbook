"""Utilities for lightweight PCAP fixtures used in tests."""

from __future__ import annotations

from binascii import unhexlify
from pathlib import Path

MINIMAL_PCAP_HEX = (
    "d4c3b2a1020004000000000000000000ffff00000100000000f1536540e2010047000000"
    "47000000ffffffffffff00112233445508004500003900004000401120a40a000001080808"
    "0830390035002500001a2b01000001000000000000076578616d706c6503636f6d0000010001"
)


def write_minimal_pcap(destination: Path) -> Path:
    """Materialise the minimal PCAP fixture to ``destination``."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(unhexlify(MINIMAL_PCAP_HEX))
    return destination


__all__ = ["MINIMAL_PCAP_HEX", "write_minimal_pcap"]
